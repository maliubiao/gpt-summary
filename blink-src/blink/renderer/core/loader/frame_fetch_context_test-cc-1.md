Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a larger test file. This code seems to be testing the behavior of how the Blink rendering engine adds specific HTTP headers (Client Hints) to resource requests based on various browser settings and conditions.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code is primarily concerned with testing the addition of HTTP headers like `Device-Memory`, `Sec-CH-Device-Memory`, `DPR`, `Sec-CH-DPR`, `Width`, `Sec-CH-Width`, `Viewport-Width`, `Sec-CH-Viewport-Width`, `Sec-CH-UA-*`, `Sec-CH-Prefers-Color-Scheme`, `Sec-CH-Prefers-Reduced-Motion`, `Sec-CH-Prefers-Reduced-Transparency`, and `Save-Data`.

2. **Recognize the Testing Framework:** The code uses `TEST_P` and `TEST_F`, indicating it's part of a testing framework, likely Google Test. The `ExpectHeader` function strongly suggests it's asserting the presence and value of specific headers in a request.

3. **Understand the Context:** The file path `blink/renderer/core/loader/frame_fetch_context_test.cc` gives context. It's about testing the `FrameFetchContext`, which is responsible for handling resource fetching within a frame.

4. **Analyze Individual Test Cases:**  Each `TEST_P` block seems to focus on a specific set of client hints and the conditions under which they are added or not added. Key observations:
    * **Device Memory:** Tests how the `Device-Memory` and `Sec-CH-Device-Memory` headers are added based on the simulated device memory.
    * **DPR (Device Pixel Ratio):** Tests the `DPR` and `Sec-CH-DPR` headers and how they are influenced by zoom level and whether the request is secure.
    * **Resource Width:** Tests the `Width` and `Sec-CH-Width` headers and how they relate to the intended resource width and zoom level.
    * **Viewport Width:** Tests the `Viewport-Width` and `Sec-CH-Viewport-Width` headers and how they reflect the viewport size.
    * **User-Agent Hints (`Sec-CH-UA-*`):** Tests various UA-related hints and how they require explicit opt-in via `ClientHintsPreferences`. Also notes the special case of `Sec-CH-UA` being sent for secure requests.
    * **Prefers-* Hints:** Tests `Sec-CH-Prefers-Color-Scheme`, `Sec-CH-Prefers-Reduced-Motion`, and `Sec-CH-Prefers-Reduced-Transparency` and how they reflect user preferences.
    * **All Hints:** Tests the combined effect of enabling multiple client hints.
    * **Permissions Policy:** Tests how Permissions Policy (`ch-*`) influences which third-party origins receive client hints.
    * **Insecure Context:** Tests that client hints are generally not sent over insecure connections, even with permissions policy.
    * **Save-Data:** Tests the addition of the `Save-Data` header when the data saver is enabled.

5. **Identify Relationships to Web Technologies:**
    * **JavaScript:** While not directly present in this snippet, the client hints being tested are often controlled or influenced by JavaScript execution in the browser. For example, JavaScript could trigger a re-render that leads to a new request with updated client hints.
    * **HTML:** The initial HTML page load is the starting point for these requests. The `ClientHintsPreferences` might be set based on `<meta>` tags with `http-equiv="Client-Hints"` or via HTTP headers sent with the HTML document.
    * **CSS:** CSS media queries can trigger changes in layout and potentially influence client hints like viewport width. `prefers-color-scheme` and `prefers-reduced-motion` directly relate to CSS features.

6. **Infer Logic and Assumptions:** The tests make assumptions about the expected behavior of the browser when certain settings are enabled or disabled. For instance, when `SetPhysicalMemoryMBForTesting` is called, the tests expect the `Device-Memory` header to reflect that value (with some rounding or bucketing).

7. **Consider User/Programming Errors:**  A common user error might be a web developer forgetting to enable client hints via the appropriate mechanisms (HTTP headers or meta tags) if they expect them to be present. A programming error within the Blink engine itself could result in incorrect header values or the absence of expected headers.

8. **Trace User Actions:**  While the code doesn't directly show user actions, the tests simulate the effects of user actions like:
    * **Visiting a website:** This initiates the initial request.
    * **Changing browser settings:** Enabling data saver, setting a preferred color scheme, etc.
    * **Zooming in/out:** This affects the DPR.
    * **Resizing the browser window:** This affects the viewport width.

9. **Synthesize a Summary:** Based on the above analysis, I can now create a concise summary of the code's functionality.
这是目录为blink/renderer/core/loader/frame_fetch_context_test.cc的chromium blink引擎源代码文件的第2部分，它延续了对 `FrameFetchContext` 类的功能测试，特别是关于 **客户端提示 (Client Hints)** 的行为。

**功能归纳:**

这部分代码主要集中在测试 `FrameFetchContext` 如何根据各种条件和配置来添加和管理 HTTP 请求头中的客户端提示信息。它测试了以下方面的功能：

* **监控和发送设备内存提示 (Device Memory Hints):**  验证在不同设备内存配置下，`Device-Memory` 和 `Sec-CH-Device-Memory` 这两个请求头是否正确添加以及它们的值是否正确。
* **监控和发送设备像素比提示 (DPR Hints):** 验证 `DPR` 和 `Sec-CH-DPR` 请求头在开启发送选项以及设置不同的布局缩放因子时的行为。同时也测试了在非安全连接 (HTTP) 下，这些提示头是否被发送。
* **监控和发送资源宽度提示 (Resource Width Hints):** 验证 `Width` 和 `Sec-CH-Width` 请求头在开启发送选项以及设置不同的布局缩放因子和预期资源宽度时的行为。
* **监控和发送视口宽度提示 (Viewport Width Hints):** 验证 `Viewport-Width` 和 `Sec-CH-Viewport-Width` 请求头在开启发送选项以及设置不同的视口尺寸时的行为。
* **监控和发送用户代理提示 (User-Agent Hints):** 验证各种 `Sec-CH-UA-*` 请求头（例如 `Sec-CH-UA-Arch`, `Sec-CH-UA-Platform-Version`, `Sec-CH-UA-Model`, `Sec-CH-UA-Form-Factors`）在开启不同发送选项时的行为。特别强调了 `Sec-CH-UA` 在安全连接下总是发送。
* **监控和发送颜色偏好提示 (Prefers Color Scheme Hint):** 验证 `Sec-CH-Prefers-Color-Scheme` 请求头在开启发送选项以及设置不同的颜色偏好时的行为。
* **监控和发送降低动画偏好提示 (Prefers Reduced Motion Hint):** 验证 `Sec-CH-Prefers-Reduced-Motion` 请求头在开启发送选项以及设置不同的降低动画偏好时的行为。
* **监控和发送降低透明度偏好提示 (Prefers Reduced Transparency Hint):** 验证 `Sec-CH-Prefers-Reduced-Transparency` 请求头在开启发送选项以及设置不同的降低透明度偏好时的行为。
* **监控和发送所有客户端提示 (Monitor All Hints):**  测试同时开启多个客户端提示发送选项时，所有相关的请求头是否都正确添加。
* **权限策略对客户端提示的影响 (Permissions Policy):**  测试通过 Permissions Policy (HTTP 头) 指定允许发送客户端提示的第三方域名时，客户端提示是否会被发送到这些域名。也测试了在非安全上下文中，即使有 Permissions Policy，客户端提示也不会发送到第三方域名。
* **子资源缓存策略 (SubResource Cache Policy):** 测试在不同的页面加载类型 (例如，标准加载、刷新、强制刷新、前进/后退) 下，子资源请求的缓存策略是否符合预期。
* **数据保护模式 (Save-Data):** 测试在开启和关闭数据保护模式时，`Save-Data` 请求头是否被正确添加。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**  JavaScript 可以通过 `navigator.connection` API 获取网络连接信息，这些信息会影响一些客户端提示，例如 `downlink` 和 `rtt`。虽然这段代码没有直接涉及 JavaScript，但测试的客户端提示机制是浏览器提供给 Web 开发人员优化性能的工具，而 JavaScript 在这些优化中扮演着重要角色。例如，JavaScript 可以根据客户端提示加载不同大小的图片。
* **HTML:**  HTML 的 `<meta>` 标签可以用来设置客户端提示策略，例如：
  ```html
  <meta http-equiv="Client-Hints" content="dpr, viewport-width">
  ```
  这个标签会指示浏览器在后续请求中包含 DPR 和视口宽度客户端提示。这段测试代码模拟了这种策略的影响。
* **CSS:** CSS 媒体查询可以用来适配不同的设备特性。例如，可以使用 `prefers-color-scheme` 媒体查询来为浅色和深色模式提供不同的样式。对应的，测试代码也在验证 `Sec-CH-Prefers-Color-Scheme` 客户端提示的正确发送，这使得服务器能够根据用户的颜色偏好提供优化的资源。

**逻辑推理 (假设输入与输出):**

**假设输入:**

1. **设备内存设置为 4096 MB。**
2. **开启发送设备内存客户端提示的选项。**
3. **发起一个到 `https://www.example.com/1.gif` 的请求。**

**输出:**

```
请求头中会包含:
Device-Memory: 4
Sec-CH-Device-Memory: 4
```

**用户或编程常见的使用错误举例说明:**

* **用户错误:** 用户可能在浏览器设置中禁用了发送某些客户端提示，导致网站无法根据用户的设备特性或偏好提供优化的体验。例如，用户禁用了发送设备内存信息，网站就无法根据用户设备的内存大小来提供不同质量的图片。
* **编程错误:** Web 开发者可能错误地配置了 Permissions Policy，导致客户端提示没有发送到预期的第三方域名，或者意外地发送到了不应该发送的域名。例如，开发者可能在 Permissions Policy 中错误地拼写了域名，导致客户端提示无法正确地传递给 CDN 服务器。

**用户操作到达这里的调试线索:**

1. **用户在浏览器地址栏输入 `https://www.example.com` 并访问该网站。**
2. **网站的 HTML 中可能包含请求图片的标签，例如 `<img src="1.gif">`。**
3. **Blink 引擎开始解析 HTML，遇到图片标签后，会创建一个资源请求。**
4. **`FrameFetchContext` 对象负责处理该资源请求，并根据当前浏览器的设置（例如，是否开启发送客户端提示）以及页面的策略（例如，Permissions Policy）来决定是否添加客户端提示头。**
5. **如果调试过程中发现客户端提示头没有按预期发送，开发者可以检查以下内容：**
    * 浏览器的客户端提示设置是否已启用。
    * 页面的 HTTP 响应头是否包含了正确的 `Accept-CH` 或 `Permissions-Policy` 头。
    * 页面的加载上下文是否安全（HTTPS）。
    * 相关的 Blink 代码逻辑，例如 `FrameFetchContext::AddClientHintsHeaders()` 方法，以查看客户端提示头是如何被添加的。

总而言之，这部分测试代码细致地验证了 Blink 引擎在处理客户端提示方面的各种场景，确保浏览器能够正确地发送这些提示信息，从而帮助 Web 开发者构建更高效、更用户友好的 Web 应用。

Prompt: 
```
这是目录为blink/renderer/core/loader/frame_fetch_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
pdateFrom(preferences);
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(4096);
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", true, "4");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Device-Memory", true,
               "4");
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(2048);
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", true, "2");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Device-Memory", true,
               "2");
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(64385);
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", true, "8");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Device-Memory", true,
               "8");
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(768);
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", true, "0.5");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Device-Memory", true,
               "0.5");
  ExpectHeader("https://www.example.com/1.gif", "DPR", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-DPR", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Viewport-Width", false,
               "");
}

TEST_P(FrameFetchContextHintsTest, MonitorDPRHints) {
  ExpectHeader("https://www.example.com/1.gif", "DPR", false, "");
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDpr_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDpr);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  ExpectHeader("https://www.example.com/1.gif", "DPR", true, "1");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-DPR", true, "1");
  document->GetFrame()->SetLayoutZoomFactor(2.5);
  ExpectHeader("https://www.example.com/1.gif", "DPR", true, "2.5");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-DPR", true, "2.5");
  ExpectHeader("https://www.example.com/1.gif", "Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Viewport-Width", false,
               "");
}

TEST_P(FrameFetchContextHintsTest, MonitorDPRHintsInsecureTransport) {
  ExpectHeader("http://www.example.com/1.gif", "DPR", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-DPR", false, "");
  document->GetFrame()->SetLayoutZoomFactor(2.5);
  ExpectHeader("http://www.example.com/1.gif", "DPR", false, "  ");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-DPR", false, "  ");
  ExpectHeader("http://www.example.com/1.gif", "Width", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Width", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Viewport-Width", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Viewport-Width", false,
               "");
}

TEST_P(FrameFetchContextHintsTest, MonitorResourceWidthHints) {
  ExpectHeader("https://www.example.com/1.gif", "Width", false, "");
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kResourceWidth_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kResourceWidth);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  ExpectHeader("https://www.example.com/1.gif", "Width", true, "500", 500);
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Width", true, "500",
               500);
  ExpectHeader("https://www.example.com/1.gif", "Width", true, "667", 666.6666);
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Width", true, "667",
               666.6666);
  ExpectHeader("https://www.example.com/1.gif", "DPR", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-DPR", false, "");

  document->GetFrame()->SetLayoutZoomFactor(2.5);
  ExpectHeader("https://www.example.com/1.gif", "Width", true, "1250", 500);
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Width", true, "1250",
               500);
  ExpectHeader("https://www.example.com/1.gif", "Width", true, "1667",
               666.6666);
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Width", true, "1667",
               666.6666);
}

TEST_P(FrameFetchContextHintsTest, MonitorViewportWidthHints) {
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", false, "");
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kViewportWidth_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kViewportWidth);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", true, "500");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Viewport-Width", true,
               "500");
  dummy_page_holder->GetFrameView().SetLayoutSizeFixedToFrameSize(false);
  dummy_page_holder->GetFrameView().SetLayoutSize(gfx::Size(800, 800));
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", true, "800");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Viewport-Width", true,
               "800");
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", true, "800",
               666.6666);
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Viewport-Width", true,
               "800", 666.6666);
  ExpectHeader("https://www.example.com/1.gif", "DPR", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-DPR", false, "");
}

TEST_P(FrameFetchContextHintsTest, MonitorUAHints) {
  // `Sec-CH-UA` is always sent for secure requests
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA", true, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA", false, "");

  // `Sec-CH-UA-*` requires opt-in.
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
               false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
               false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Form-Factors", false,
               "");
  ExpectHeader("http://www.example.com/0.gif", "Sec-CH-UA-Model", false, "");
  ExpectHeader("http://www.example.com/0.gif", "Sec-CH-UA-Form-Factors", false,
               "");

  {
    ClientHintsPreferences preferences;
    preferences.SetShouldSend(network::mojom::WebClientHintsType::kUAArch);
    document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Arch", true,
                 EmptyString());
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");

    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");
  }

  {
    ClientHintsPreferences preferences;
    document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform", true,
                 EmptyString());
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");

    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");
  }

  {
    ClientHintsPreferences preferences;
    preferences.SetShouldSend(
        network::mojom::WebClientHintsType::kUAPlatformVersion);
    document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 true, EmptyString());
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");

    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");
  }

  {
    ClientHintsPreferences preferences;
    preferences.SetShouldSend(network::mojom::WebClientHintsType::kUAModel);
    document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Model", true,
                 EmptyString());
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");

    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");
  }

  {
    ClientHintsPreferences preferences;
    preferences.SetShouldSend(
        network::mojom::WebClientHintsType::kUAFormFactors);
    document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 true, "");

    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
                 false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
    ExpectHeader("http://www.example.com/1.gif", "Sec-CH-UA-Form-Factors",
                 false, "");
  }
}

TEST_P(FrameFetchContextHintsTest, MonitorPrefersColorSchemeHint) {
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Color-Scheme",
               false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Prefers-Color-Scheme",
               false, "");

  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersColorScheme);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Color-Scheme",
               true, "light");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Prefers-Color-Scheme",
               false, "");

  document->GetSettings()->SetPreferredColorScheme(
      mojom::PreferredColorScheme::kDark);
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Color-Scheme",
               true, "dark");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Prefers-Color-Scheme",
               false, "");
}

TEST_P(FrameFetchContextHintsTest, MonitorPrefersReducedMotionHint) {
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               false, "");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               false, "");

  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersReducedMotion);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               true, "no-preference");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               false, "");

  document->GetSettings()->SetPrefersReducedMotion(true);
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               true, "reduce");
  ExpectHeader("http://www.example.com/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               false, "");
}

TEST_P(FrameFetchContextHintsTest, MonitorPrefersReducedTransparencyHint) {
  ExpectHeader("https://www.example.com/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", false, "");
  ExpectHeader("http://www.example.com/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", false, "");

  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersReducedTransparency);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

  ExpectHeader("https://www.example.com/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", true, "no-preference");
  ExpectHeader("http://www.example.com/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", false, "");

  document->GetSettings()->SetPrefersReducedTransparency(true);
  ExpectHeader("https://www.example.com/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", true, "reduce");
  ExpectHeader("http://www.example.com/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", false, "");
}

TEST_P(FrameFetchContextHintsTest, MonitorAllHints) {
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", false, "");
  ExpectHeader("https://www.example.com/1.gif", "DPR", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Width", false, "");
  ExpectHeader("https://www.example.com/1.gif", "rtt", false, "");
  ExpectHeader("https://www.example.com/1.gif", "downlink", false, "");
  ExpectHeader("https://www.example.com/1.gif", "ect", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Arch", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
               false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Model", false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Form-Factors", false,
               "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Color-Scheme",
               false, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               false, "");
  ExpectHeader("https://www.example.com/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", false, "");

  // `Sec-CH-UA` is special.
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA", true, "");

  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDeviceMemory_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDeviceMemory);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDpr_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDpr);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kResourceWidth_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kResourceWidth);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kViewportWidth_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kViewportWidth);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kRtt_DEPRECATED);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDownlink_DEPRECATED);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kEct_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kUA);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kUAArch);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kUAPlatformVersion);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kUAModel);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kUAFormFactors);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersColorScheme);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersReducedMotion);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersReducedTransparency);
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(4096);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", true, "4");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Device-Memory", true,
               "4");
  ExpectHeader("https://www.example.com/1.gif", "DPR", true, "1");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-DPR", true, "1");
  ExpectHeader("https://www.example.com/1.gif", "Width", true, "400", 400);
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Width", true, "400",
               400);
  ExpectHeader("https://www.example.com/1.gif", "Viewport-Width", true, "500");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Viewport-Width", true,
               "500");

  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA", true, "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Arch", true,
               EmptyString());
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform", true,
               EmptyString());
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Platform-Version",
               true, EmptyString());
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Model", true,
               EmptyString());
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-UA-Form-Factors", true,
               "");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Color-Scheme",
               true, "light");
  ExpectHeader("https://www.example.com/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               true, "no-preference");
  ExpectHeader("https://www.example.com/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", true, "no-preference");

  // Value of network quality client hints may vary, so only check if the
  // header is present and the values are non-negative/non-empty.
  bool conversion_ok = false;
  int rtt_header_value = GetHeaderValue("https://www.example.com/1.gif", "rtt")
                             .ToIntStrict(&conversion_ok);
  EXPECT_TRUE(conversion_ok);
  EXPECT_LE(0, rtt_header_value);

  float downlink_header_value =
      GetHeaderValue("https://www.example.com/1.gif", "downlink")
          .ToFloat(&conversion_ok);
  EXPECT_TRUE(conversion_ok);
  EXPECT_LE(0, downlink_header_value);

  EXPECT_LT(
      0u,
      GetHeaderValue("https://www.example.com/1.gif", "ect").Ascii().length());
}

// Verify that the client hints should be attached for third-party subresources
// fetched over secure transport, when specifically allowed by permissions
// policy.
TEST_P(FrameFetchContextHintsTest, MonitorAllHintsPermissionsPolicy) {
  RecreateFetchContext(
      KURL("https://www.example.com/"),
      "ch-dpr *; ch-device-memory *; ch-downlink *; ch-ect *; ch-rtt *; ch-ua "
      "*; ch-ua-arch *; ch-ua-platform *; ch-ua-platform-version *; "
      "ch-ua-model *; ch-viewport-width *; ch-width *; ch-prefers-color-scheme "
      "*; ch-prefers-reduced-motion *; ch-prefers-reduced-transparency *");
  document->GetSettings()->SetScriptEnabled(true);
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDeviceMemory_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDeviceMemory);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDpr_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDpr);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kResourceWidth_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kResourceWidth);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kViewportWidth_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kViewportWidth);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kRtt_DEPRECATED);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDownlink_DEPRECATED);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kEct_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kUA);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kUAArch);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kUAPlatformVersion);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kUAModel);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersColorScheme);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersReducedMotion);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kPrefersReducedTransparency);
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(4096);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);

  // Verify that all client hints are sent to a third-party origin, with this
  // permissions policy header.
  ExpectHeader("https://www.example.net/1.gif", "DPR", true, "1");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-DPR", true, "1");
  ExpectHeader("https://www.example.net/1.gif", "Device-Memory", true, "4");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Device-Memory", true,
               "4");

  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA", true, "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA-Arch", true,
               EmptyString());
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA-Platform", true,
               EmptyString());
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA-Platform-Version",
               true, EmptyString());
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA-Model", true,
               EmptyString());
  ExpectHeader("https://www.example.net/1.gif", "Width", true, "400", 400);
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Width", true, "400",
               400);
  ExpectHeader("https://www.example.net/1.gif", "Viewport-Width", true, "500");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Viewport-Width", true,
               "500");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Prefers-Color-Scheme",
               true, "light");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               true, "no-preference");
  ExpectHeader("https://www.example.net/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", true, "no-preference");

  // Value of network quality client hints may vary, so only check if the
  // header is present and the values are non-negative/non-empty.
  bool conversion_ok = false;
  int rtt_header_value = GetHeaderValue("https://www.example.com/1.gif", "rtt")
                             .ToIntStrict(&conversion_ok);
  EXPECT_TRUE(conversion_ok);
  EXPECT_LE(0, rtt_header_value);

  float downlink_header_value =
      GetHeaderValue("https://www.example.com/1.gif", "downlink")
          .ToFloat(&conversion_ok);
  EXPECT_TRUE(conversion_ok);
  EXPECT_LE(0, downlink_header_value);

  EXPECT_LT(
      0u,
      GetHeaderValue("https://www.example.com/1.gif", "ect").Ascii().length());
}

// Verify that only the specifically allowed client hints are attached for
// third-party subresources fetched over secure transport.
TEST_P(FrameFetchContextHintsTest, MonitorSomeHintsPermissionsPolicy) {
  RecreateFetchContext(KURL("https://www.example.com/"),
                       "ch-device-memory 'self' https://www.example.net");
  document->GetSettings()->SetScriptEnabled(true);
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDeviceMemory_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDeviceMemory);
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDpr_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDpr);
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(4096);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  // With a permissions policy header, the client hints should be sent to the
  // declared third party origins.
  ExpectHeader("https://www.example.net/1.gif", "Device-Memory", true, "4");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Device-Memory", true,
               "4");
  ExpectHeader("https://www.someother-example.com/1.gif", "Device-Memory",
               false, "");
  ExpectHeader("https://www.someother-example.com/1.gif",
               "Sec-CH-Device-Memory", false, "");
  // `Sec-CH-UA` is special.
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA", true, "");

  // Other hints not declared in the policy are still not attached.
  ExpectHeader("https://www.example.net/1.gif", "downlink", false, "");
  ExpectHeader("https://www.example.net/1.gif", "ect", false, "");
  ExpectHeader("https://www.example.net/1.gif", "DPR", false, "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-DPR", false, "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA-Arch", false, "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA-Platform-Version",
               false, "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-UA-Model", false, "");
  ExpectHeader("https://www.example.net/1.gif", "Width", false, "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Width", false, "");
  ExpectHeader("https://www.example.net/1.gif", "Viewport-Width", false, "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Viewport-Width", false,
               "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Prefers-Color-Scheme",
               false, "");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Prefers-Reduced-Motion",
               false, "");
  ExpectHeader("https://www.example.net/1.gif",
               "Sec-CH-Prefers-Reduced-Transparency", false, "");
}

// Verify that the client hints are not attached for third-party subresources
// fetched over insecure transport, even when specifically allowed by
// permissions policy.
TEST_P(FrameFetchContextHintsTest,
       MonitorHintsPermissionsPolicyInsecureContext) {
  RecreateFetchContext(KURL("https://www.example.com/"), "ch-device-memory *");
  document->GetSettings()->SetScriptEnabled(true);
  ExpectHeader("https://www.example.com/1.gif", "Device-Memory", false, "");
  ClientHintsPreferences preferences;
  preferences.SetShouldSend(
      network::mojom::WebClientHintsType::kDeviceMemory_DEPRECATED);
  preferences.SetShouldSend(network::mojom::WebClientHintsType::kDeviceMemory);
  document->GetFrame()->GetClientHintsPreferences().UpdateFrom(preferences);
  ApproximatedDeviceMemory::SetPhysicalMemoryMBForTesting(4096);
  // Device-Memory hint in this case is sent to all (and only) secure origins.
  ExpectHeader("https://www.example.net/1.gif", "Device-Memory", true, "4");
  ExpectHeader("https://www.example.net/1.gif", "Sec-CH-Device-Memory", true,
               "4");
  ExpectHeader("http://www.example.net/1.gif", "Device-Memory", false, "");
  ExpectHeader("http://www.example.net/1.gif", "Sec-CH-Device-Memory", false,
               "");
}

TEST_F(FrameFetchContextTest, SubResourceCachePolicy) {
  // Reset load event state: if the load event is finished, we ignore the
  // DocumentLoader load type.
  document->open();
  ASSERT_FALSE(document->LoadEventFinished());

  // Default case
  ResourceRequest request("http://www.example.com/mock");
  EXPECT_EQ(mojom::FetchCacheMode::kDefault,
            GetFetchContext()->ResourceRequestCachePolicy(
                request, ResourceType::kMock, FetchParameters::kNoDefer));

  // WebFrameLoadType::kReload should not affect sub-resources
  document->Loader()->SetLoadType(WebFrameLoadType::kReload);
  EXPECT_EQ(mojom::FetchCacheMode::kDefault,
            GetFetchContext()->ResourceRequestCachePolicy(
                request, ResourceType::kMock, FetchParameters::kNoDefer));

  // Conditional request
  document->Loader()->SetLoadType(WebFrameLoadType::kStandard);
  ResourceRequest conditional("http://www.example.com/mock");
  conditional.SetHttpHeaderField(http_names::kIfModifiedSince,
                                 AtomicString("foo"));
  EXPECT_EQ(mojom::FetchCacheMode::kValidateCache,
            GetFetchContext()->ResourceRequestCachePolicy(
                conditional, ResourceType::kMock, FetchParameters::kNoDefer));

  // WebFrameLoadType::kReloadBypassingCache
  document->Loader()->SetLoadType(WebFrameLoadType::kReloadBypassingCache);
  EXPECT_EQ(mojom::FetchCacheMode::kBypassCache,
            GetFetchContext()->ResourceRequestCachePolicy(
                request, ResourceType::kMock, FetchParameters::kNoDefer));

  // WebFrameLoadType::kReloadBypassingCache with a conditional request
  document->Loader()->SetLoadType(WebFrameLoadType::kReloadBypassingCache);
  EXPECT_EQ(mojom::FetchCacheMode::kBypassCache,
            GetFetchContext()->ResourceRequestCachePolicy(
                conditional, ResourceType::kMock, FetchParameters::kNoDefer));

  // Back/forward navigation
  document->Loader()->SetLoadType(WebFrameLoadType::kBackForward);
  EXPECT_EQ(mojom::FetchCacheMode::kForceCache,
            GetFetchContext()->ResourceRequestCachePolicy(
                request, ResourceType::kMock, FetchParameters::kNoDefer));

  // Back/forward navigation with a conditional request
  document->Loader()->SetLoadType(WebFrameLoadType::kBackForward);
  EXPECT_EQ(mojom::FetchCacheMode::kForceCache,
            GetFetchContext()->ResourceRequestCachePolicy(
                conditional, ResourceType::kMock, FetchParameters::kNoDefer));
}

// Tests if "Save-Data" header is correctly added on the first load and reload.
TEST_P(FrameFetchContextHintsTest, EnableDataSaver) {
  GetNetworkStateNotifier().SetSaveDataEnabledOverride(true);
  // Recreate the fetch context so that the updated save data settings are read.
  RecreateFetchContext(KURL("https://www.example.com/"));
  document->GetSettings()->SetScriptEnabled(true);

  ExpectHeader("https://www.example.com/", "Save-Data", true, "on");

  // Subsequent call to addAdditionalRequestHeaders should not append to the
  // save-data header.
  ExpectHeader("https://www.example.com/", "Save-Data", true, "on");
}

// Tests if "Save-Data" header is not added when the data saver is disabled.
TEST_P(FrameFetchContextHintsTest, DisabledDataSaver) {
  GetNetworkStateNotifier().SetSaveDataEnabledOverride(false);
  // Recreate the fetch context so that the updated save data settings are read.
  RecreateFetchContext(KURL("https://www.example.com/"));
  document->GetSettings()->SetScriptEnabled(true);

  ExpectHeader("https://www.example.com/", "Save-Data", false, "");
}

// Tests if reload variants can reflect the
"""


```