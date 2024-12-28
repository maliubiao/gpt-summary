Response:
The user wants a summary of the functionality of the provided C++ code snippet from `document_test.cc`. This is part 2 of 3, implying I should focus on the features demonstrated in this specific chunk of code.

Here's a breakdown of the code's functionalities:

1. **Mutation Observers**: Tests how `MutationObserver` tracks changes to character data nodes (like text nodes).
2. **Theme Color**: Tests how the document's theme color (defined by the `<meta name="theme-color">` tag) is retrieved.
3. **Validation Message Cleanup**: Tests the cleanup process for validation messages when a document is unloaded, especially when an `unload` event handler tries to report validity.
4. **Paint Location Data Validity**: Tests the logic for ensuring paint location data is valid, specifically focusing on scenarios involving sticky positioning and when compositor inputs need to be cleaned.
5. **Viewport Style Propagation**: Tests that changes in element styles don't unnecessarily trigger style recalculations for viewport propagation.
6. **Sandboxed `srcdoc` User Counts**: Tests whether using relative URLs within sandboxed `srcdoc` iframes correctly triggers use counters for specific features. This also covers cases with `<base>` elements.
7. **Script Execution in Sandboxed Frames**: Tests whether scripts can be executed in isolated worlds within a sandboxed frame, especially when a Content Security Policy (CSP) is present for the isolated world.
8. **`elementFromPoint` on Scrollbar**: Tests the behavior of `document.elementFromPoint()` when the hit point is on a scrollbar.
9. **`elementFromPoint` with Page Zoom**: Tests how page zoom affects the results of `document.elementFromPoint()`.
10. **`prefers-color-scheme` Media Query**: Tests how changes in the preferred color scheme are reflected in the `prefers-color-scheme` media query.
11. **Find-in-Page UKM**: Tests the recording of User Keyed Metrics (UKM) related to the find-in-page functionality, including whether a search was initiated and if there were matches in content-visibility:auto regions.
12. **Find-in-Page UKM in Iframe**: Similar to the previous point, but specifically for find-in-page operations within an iframe.
13. **Page Margins with Device Scale Factor**: Tests how device scale factors affect page margins during printing.
14. **`hasPrivateToken` API**: Tests various scenarios for the `document.hasPrivateToken()` API, which is related to Privacy Preserving Token (Trust Token) functionality. This includes successful calls, error conditions (like Mojo disconnects, invalid arguments, resource exhaustion, and generic errors), and cases where the API is called from non-HTTP/HTTPS documents.
15. **`hasRedemptionRecord` API**: Tests various scenarios for the `document.hasRedemptionRecord()` API, another part of the Trust Token functionality. Similar to `hasPrivateToken`, it covers success and different error conditions.
这是 `blink/renderer/core/dom/document_test.cc` 文件的第二部分，主要包含以下功能测试：

**1. `UpdatedCharacterDataRecords()` 测试：验证 `MutationObserver` 对 CharacterData 节点（例如文本节点）的更新记录。**

*   **功能:** 测试 `MutationObserver` 是否能正确记录 `CharacterData` 节点（例如 `Text` 节点、`Comment` 节点）的数据变化，包括删除、插入和替换。
*   **与 JavaScript 的关系:**  `MutationObserver` 是一个 JavaScript API，用于异步监听 DOM 树的变化。这个测试验证了 Blink 引擎中 `MutationObserver` 的 C++ 实现与 JavaScript API 的预期行为一致。
*   **假设输入与输出:**
    *   **假设输入:** 一个包含文本节点的 DOM 树，并且注册了一个监听 `characterData` 和 `characterDataOldValue` 的 `MutationObserver`。对该文本节点进行 `deleteData`, `insertData`, `replaceData` 操作。
    *   **预期输出:** `observer.UpdatedCharacterDataRecords()` 将包含一系列记录，每个记录包含修改的节点、偏移量、旧数据长度、新数据长度。例如，删除操作的 `new_length_` 为 0，插入操作的 `old_length_` 为 0。
*   **用户或编程常见错误:**  开发者可能错误地认为只有元素节点的增删改才会触发 `MutationObserver`，而忽略了文本节点等 `CharacterData` 节点的变化。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户与网页交互，例如在一个可编辑的文本区域输入、删除或修改文本。
    2. 网页的 JavaScript 代码中使用了 `MutationObserver` 监听了这些文本节点的变化。
    3. Blink 引擎的 DOM 操作模块会检测到这些变化并通知 `MutationObserver`。
    4. 这个测试验证了 `MutationObserver` 内部的 C++ 实现是否正确地记录了这些变化。

**2. `ThemeColor` 测试：验证是否能正确获取 `<meta name="theme-color">` 的值。**

*   **功能:** 测试 Blink 引擎是否能正确解析 HTML 中 `<meta name="theme-color" content="...">` 标签，并获取其 `content` 属性的值作为文档的主题颜色。
*   **与 HTML 的关系:** `<meta name="theme-color">` 是 HTML 中用于定义网站主题颜色的标签，浏览器可以使用这个颜色自定义用户界面的显示。
*   **假设输入与输出:**
    *   **假设输入:** 包含 `<meta name="theme-color" content="#00ff00">` 标签的 HTML 文档，该标签可以位于 `<head>` 或 `<body>` 中。
    *   **预期输出:** `GetDocument().ThemeColor()` 将返回一个表示亮绿色的 `Color` 对象。
*   **用户或编程常见错误:**  开发者可能在 HTML 中拼写错误 `theme-color` 或 `content` 属性，或者使用了浏览器不支持的颜色格式。
*   **用户操作如何到达这里 (调试线索):**
    1. 网站开发者在 HTML 中添加了 `<meta name="theme-color">` 标签来设置网站的主题颜色。
    2. 浏览器加载解析该 HTML 文档。
    3. Blink 引擎的 HTML 解析器会识别该 meta 标签并提取主题颜色信息。
    4. 这个测试验证了 Blink 引擎的解析器是否能正确处理该标签。

**3. `ValidationMessageCleanup` 测试：验证验证消息的清理机制。**

*   **功能:** 测试当文档被卸载时，与表单验证相关的消息是否能被正确清理，即使在 `unload` 事件处理程序中尝试显示验证消息。
*   **与 JavaScript 的关系:**  涉及到 JavaScript 的 `window.onunload` 事件和表单元素的 `reportValidity()` 方法。
*   **假设输入与输出:**
    *   **假设输入:**  一个包含带有 `required` 属性的 `<input>` 元素和一个设置了 `window.onunload` 事件处理程序的 `<script>` 标签的 HTML 文档。`unload` 处理程序会尝试调用 `input.reportValidity()`。
    *   **预期输出:**  在文档卸载 (`DetachDocument()`) 后，即使 `unload` 处理程序尝试显示验证消息，`mock_client->show_validation_message_was_called` 仍然为 `false`，并且 `mock_client->document_detached_was_called` 为 `true`。
*   **用户或编程常见错误:**  开发者可能在 `unload` 事件处理程序中执行耗时的操作或尝试访问已卸载的文档元素，这可能会导致错误。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户浏览到一个包含需要验证的表单的页面。
    2. 该页面可能有一个 `unload` 事件处理程序，尝试在页面卸载前进行一些操作。
    3. 用户导航到其他页面或关闭浏览器标签页，导致当前文档被卸载。
    4. 这个测试验证了 Blink 引擎在文档卸载时的清理逻辑，确保不会在卸载过程中尝试显示验证消息。

**4. `EnsurePaintLocationDataValidForNodeCompositingInputsOnlyWhenNecessary` 测试：验证 `EnsurePaintLocationDataValidForNode` 方法只在必要时清理合成器输入。**

*   **功能:** 测试 `Document::EnsurePaintLocationDataValidForNode` 方法在请求节点的绘制位置信息时，是否只在必要的情况下（例如，当涉及 sticky 定位元素时）才清理合成器输入，以优化性能。
*   **与 CSS 的关系:**  涉及到 CSS 的 `position: sticky;` 属性。
*   **假设输入与输出:**
    *   **假设输入:**  包含一个 sticky 定位元素及其父元素和兄弟元素的 DOM 结构。
    *   **预期输出:**  请求非 sticky 元素或其祖先的绘制位置信息时，文档生命周期最多只会前进到 `kLayoutClean` 状态。请求 sticky 元素或其后代的绘制位置信息时，会触发合成器输入的清理，文档生命周期也会达到或超过 `kLayoutClean` 状态。
*   **用户或编程常见错误:**  开发者可能过度使用 sticky 定位，导致频繁的合成器输入清理，影响性能。
*   **用户操作如何到达这里 (调试线索):**
    1. 网页使用了 sticky 定位效果，当用户滚动页面时，sticky 元素会吸附在视口顶部。
    2. Blink 引擎在渲染过程中需要确定元素的位置信息，包括 sticky 元素。
    3. `EnsurePaintLocationDataValidForNode` 方法会被调用以确保位置信息是最新的。
    4. 这个测试验证了该方法是否针对 sticky 定位进行了优化，避免不必要的合成器输入清理。

**5. `ViewportPropagationNoRecalc` 测试：验证计算样式的差异不会触发不必要的视口样式传播。**

*   **功能:** 测试当 `<html>` 和 `<body>` 元素的 `direction` 计算样式不同时，重新计算文档中其他元素的样式不会触发不必要的视口样式传播。
*   **与 CSS 的关系:**  涉及到 CSS 的 `direction` 属性，用于指定文本方向。
*   **假设输入与输出:**
    *   **假设输入:**  一个 `<body>` 元素设置了 `direction: rtl;` 样式，以及一个需要重新计算样式的 `<div>` 元素。
    *   **预期输出:**  在重新计算 `<div>` 元素的样式后，`GetDocument().GetStyleEngine().StyleForElementCount()` 的增量应该只为 1，表示只重新计算了 `<div>` 元素的样式，没有触发额外的视口样式传播。
*   **用户或编程常见错误:**  开发者可能在 `<html>` 和 `<body>` 元素上设置了不同的 `direction` 值，但期望样式计算能高效地处理这种情况。
*   **用户操作如何到达这里 (调试线索):**
    1. 网页可能需要支持从右到左的语言，因此在 `<body>` 元素上设置了 `direction: rtl;`。
    2. 由于某些原因，`<html>` 元素的 `direction` 值可能与 `<body>` 不同。
    3. JavaScript 修改了页面中某个元素的样式，触发了样式重新计算。
    4. 这个测试验证了 Blink 引擎在这种情况下是否能避免不必要的样式重算。

**6. `SandboxedSrcdocUserCounts_...` 系列测试：验证沙盒 `srcdoc` iframe 中相对 URL 的使用计数。**

*   **功能:** 测试在沙盒化的 `<iframe>` 中使用 `srcdoc` 属性加载内容时，是否正确记录了相对 URL 的使用情况。这包括有无 `<base>` 标签的情况。
*   **与 HTML 的关系:**  涉及到 HTML 的 `<iframe>` 标签和 `srcdoc` 属性，以及 `<base>` 标签。沙盒属性 (`sandbox`) 用于限制 iframe 内的内容权限。
*   **假设输入与输出:**
    *   **假设输入:**  一个父页面包含一个设置了 `sandbox` 属性的 `<iframe>`，其 `srcdoc` 属性包含带有相对 URL 的内容（例如 `<img src='image.png'>`）。有无 `<base>` 标签是不同的测试用例。
    *   **预期输出:**  在没有 `<base>` 标签的情况下，相对 URL 的使用会触发一个 use count。有 `<base>` 标签定义了基础 URL 后，相对 URL 的使用则不会触发 use count。对于绝对 URL，即使在沙盒的 `srcdoc` 中也不会触发 use count。
*   **用户或编程常见错误:**  开发者可能不清楚在沙盒化的 `srcdoc` iframe 中使用相对 URL 的影响。
*   **用户操作如何到达这里 (调试线索):**
    1. 网站开发者为了隔离嵌入内容，使用了带有 `sandbox` 属性的 `<iframe>`，并通过 `srcdoc` 属性动态生成 iframe 的内容。
    2. `srcdoc` 中的内容可能包含指向同源资源的相对 URL。
    3. 这个测试验证了 Blink 引擎在这种情况下是否正确处理了 URL 的使用计数。

**7. `CanExecuteScriptsWithSandboxAndIsolatedWorld` 测试：验证在沙盒和独立 World 下是否可以执行脚本。**

*   **功能:** 测试在设置了 `sandbox` 属性的页面中，是否可以在独立的 JavaScript World 中执行脚本，特别是当该 World 定义了内容安全策略 (CSP) 时。
*   **与 JavaScript 的关系:**  涉及到 JavaScript 的执行环境和内容安全策略。
*   **假设输入与输出:**
    *   **假设输入:**  一个通过 `NavigateWithSandbox` 方法加载的沙盒页面。分别创建了不带 CSP 和带有 CSP 的独立 World。
    *   **预期输出:**  主 World 和不带 CSP 的独立 World 由于沙盒限制，无法执行脚本。带有 CSP 的独立 World 可以绕过主 World 的沙盒限制执行脚本。
*   **用户或编程常见错误:**  开发者可能错误地认为沙盒会完全阻止所有脚本的执行，而忽略了独立 World 的存在和其绕过沙盒的能力。
*   **用户操作如何到达这里 (调试线索):**
    1. 网站开发者为了安全原因，使用 `sandbox` 属性创建了一个沙盒化的 iframe 或主页面。
    2. 可能需要在沙盒环境中执行一些受信任的脚本，因此使用了独立 World 并设置了 CSP。
    3. 这个测试验证了 Blink 引擎在这种沙盒和独立 World 的场景下，脚本的执行权限是否符合预期。

**8. `ElementFromPointOnScrollbar` 测试：验证 `elementFromPoint` 在滚动条上的行为。**

*   **功能:** 测试 `document.elementFromPoint()` 方法在点击到滚动条区域时的返回值。
*   **与 JavaScript 的关系:**  `document.elementFromPoint()` 是一个 JavaScript API，用于获取指定坐标下的元素。
*   **假设输入与输出:**
    *   **假设输入:**  一个页面，其内容宽度超过视口宽度，导致出现水平滚动条。分别在滚动条区域和滚动条上方的区域调用 `document.elementFromPoint()`。
    *   **预期输出:**  点击在滚动条区域时，返回 `nullptr`。点击在滚动条上方的元素内容区域时，返回对应的元素。
*   **用户或编程常见错误:**  开发者可能错误地认为点击滚动条也会返回某个元素。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户浏览到一个内容超出视口，带有滚动条的页面。
    2. 网页的 JavaScript 代码可能使用了 `document.elementFromPoint()` 来响应用户的点击事件。
    3. 用户点击了滚动条区域或其上方的元素。
    4. 这个测试验证了 `document.elementFromPoint()` 在滚动条区域的返回值是否正确。

**9. `ElementFromPointWithPageZoom` 测试：验证页面缩放时 `elementFromPoint` 的行为。**

*   **功能:** 测试在页面缩放的情况下，`document.elementFromPoint()` 方法是否能正确返回指定坐标下的元素。
*   **与 JavaScript 的关系:**  `document.elementFromPoint()` 是一个 JavaScript API。
*   **假设输入与输出:**
    *   **假设输入:**  一个设置了特定高度的 `<div>` 元素。在页面缩放前后，分别在 `<div>` 内部和外部的相同坐标调用 `document.elementFromPoint()`。
    *   **预期输出:**  无论页面是否缩放，点击在 `<div>` 内部的坐标应该返回该 `<div>` 元素，点击在外部的坐标应该返回 `<body>` 元素。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户浏览到一个页面，并使用浏览器的缩放功能进行放大或缩小。
    2. 网页的 JavaScript 代码可能使用了 `document.elementFromPoint()` 来响应用户的点击事件。
    3. 用户点击了页面上的某个位置。
    4. 这个测试验证了 `document.elementFromPoint()` 在页面缩放时的返回值是否正确。

**10. `PrefersColorSchemeChanged` 测试：验证 `prefers-color-scheme` 媒体查询的改变通知。**

*   **功能:** 测试当用户的首选配色方案改变时，`prefers-color-scheme` 媒体查询是否能正确触发监听器。
*   **与 CSS 的关系:**  涉及到 CSS 的 `prefers-color-scheme` 媒体查询。
*   **假设输入与输出:**
    *   **假设输入:**  一个注册了 `(prefers-color-scheme: dark)` 媒体查询监听器的文档。用户的首选配色方案从 light 切换到 dark。
    *   **预期输出:**  在配色方案切换后，监听器会被通知 (`listener->IsNotified()` 为 `true`)。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户在其操作系统或浏览器设置中更改了首选的配色方案（例如，从亮色模式切换到暗色模式）。
    2. 网页的 CSS 中使用了 `@media (prefers-color-scheme: dark)` 规则，或者 JavaScript 代码监听了该媒体查询的变化。
    3. Blink 引擎会检测到用户配色方案的改变，并更新媒体查询的匹配结果。
    4. 这个测试验证了 Blink 引擎是否正确地通知了监听 `prefers-color-scheme` 的代码。

**11. `FindInPageUkm` 和 `FindInPageUkmInFrame` 测试：验证查找功能相关的 UKM 记录。**

*   **功能:** 测试在页面内查找功能被使用时，是否正确记录了相关的 User Keyed Metrics (UKM)，例如是否进行了搜索，以及是否在 `content-visibility: auto` 区域找到了匹配项。
*   **与 JavaScript 的关系:**  页面内的查找功能可以通过浏览器的内置功能或 JavaScript API 触发。
*   **假设输入与输出:**
    *   **假设输入:**  用户在页面上发起查找操作。对于 `FindInPageUkmInFrame`，查找操作发生在 iframe 中。
    *   **预期输出:**  UKM 记录器会记录 "Blink.FindInPage" 事件，并包含 "DidSearch" 指标（表示是否进行了搜索）和 "DidHaveRenderSubtreeMatch" 指标（表示是否在 `content-visibility: auto` 区域找到了匹配项）。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户按下 `Ctrl+F` (或 `Cmd+F`) 快捷键，或者使用浏览器菜单中的“查找”功能，触发页面内的查找功能。
    2. 浏览器会高亮显示匹配的文本。
    3. Blink 引擎会记录与查找操作相关的 UKM 数据。
    4. 这两个测试验证了 UKM 数据是否被正确记录，包括在 iframe 中的情况。

**12. `AtPageMarginWithDeviceScaleFactor` 测试：验证设备缩放因子下的页面边距。**

*   **功能:** 测试在设置了设备缩放因子的情况下，打印页面的边距是否被正确计算。
*   **与 CSS 的关系:**  涉及到 CSS 的 `@page` 规则，用于定义打印页面的样式，包括边距。
*   **假设输入与输出:**
    *   **假设输入:**  一个设置了设备缩放因子为 2 的文档，并定义了 `@page { margin: 50px; size: 400px 10in; }`。
    *   **预期输出:**  调用 `GetDocument().GetPageDescription(0)` 获取的页面描述信息中，`margin_top`, `margin_right`, `margin_bottom`, `margin_left` 都为 50，`size` 为 `gfx::SizeF(400, 960)`。
*   **用户操作如何到达这里 (调试线索):**
    1. 用户尝试打印网页。
    2. 用户的设备可能设置了非 1 的设备缩放因子。
    3. Blink 引擎在生成打印预览或实际打印时，会考虑设备缩放因子来计算布局和样式。
    4. 这个测试验证了 Blink 引擎在处理打印页面边距时是否考虑了设备缩放因子。

**13. `HandlesDisconnectDuringHasPrivateToken` 测试：验证 `hasPrivateToken` 调用期间连接断开的处理。**

*   **功能:** 测试在 `document.hasPrivateToken()` 方法执行期间，与 Trust Token 查询服务断开连接时，Promise 是否会被正确拒绝并返回相应的错误。
*   **与 JavaScript 的关系:**  涉及到 JavaScript 的 `document.hasPrivateToken()` API 和 Promise。
*   **假设输入与输出:**
    *   **假设输入:**  调用 `document.hasPrivateToken()` 方法后，模拟 Trust Token 查询服务的连接断开。
    *   **预期输出:**  返回的 Promise 将被拒绝，并且错误类型是 `DOMException`，错误代码是 `kOperationError`。
*   **用户或编程常见错误:**  开发者可能没有考虑到 `hasPrivateToken()` 调用期间服务连接断开的情况，导致程序出现未处理的异常。
*   **用户操作如何到达这里 (调试线索):**
    1. 网页的 JavaScript 代码调用了 `document.hasPrivateToken()` 方法来检查是否存在与特定发行者关联的 Private Token (Trust Token)。
    2. 在网络请求过程中，与 Trust Token 查询服务的连接意外断开。
    3. 这个测试验证了 Blink 引擎在这种网络错误情况下是否能正确处理 `hasPrivateToken()` 的 Promise 返回。

**14. `RejectsHasPrivateTokenCallFromNonHttpNonHttpsDocument` 测试：验证从非 HTTP/HTTPS 文档调用 `hasPrivateToken` 的拒绝。**

*   **功能:** 测试从非安全上下文（例如 `file:///` 协议的文档）调用 `document.hasPrivateToken()` 方法时，是否会抛出异常。
*   **与 JavaScript 的关系:**  涉及到 JavaScript 的 `document.hasPrivateToken()` API。
*   **假设输入与输出:**
    *   **假设输入:**  一个 `file:///` 协议的文档调用 `document.hasPrivateToken()`。
    *   **预期输出:**  调用会立即抛出一个 `NotAllowedError` 类型的 `DOMException`。
*   **用户或编程常见错误:**  开发者可能在非安全上下文中使用了 `hasPrivateToken()` API。
*   **用户操作如何到达这里 (调试线索):**
    1. 开发者可能在本地打开了一个 HTML 文件 (`file:///...`)，该文件中包含了调用 `document.hasPrivateToken()` 的 JavaScript 代码。
    2. 这个测试验证了 Blink 引擎是否正确地限制了 `hasPrivateToken()` API 只能在安全的上下文中使用。

**15. `HasPrivateTokenSuccess`, `HasPrivateTokenSuccessWithFalseValue`, `HasPrivateTokenOperationError`, `HasPrivateTokenInvalidArgument`, `HasPrivateTokenResourceExhausted` 和 `HasRedemptionRecord...` 系列测试：验证 `hasPrivateToken` 和 `hasRedemptionRecord` API 的各种成功和错误场景。**

*   **功能:**  测试 `document.hasPrivateToken()` 和 `document.hasRedemptionRecord()` 方法在各种成功和错误情况下的行为，包括成功返回 `true` 或 `false`，以及在遇到操作错误、参数无效或资源耗尽等情况时返回相应的 Promise 拒绝。
*   **与 JavaScript 的关系:**  涉及到 JavaScript 的 `document.hasPrivateToken()` 和 `document.hasRedemptionRecord()` API 和 Promise。
*   **假设输入与输出:**  这些测试通过模拟不同的 Trust Token 查询服务的响应来测试各种场景。例如，`HasPrivateTokenSuccess` 模拟服务返回 `true`，`HasPrivateTokenOperationError` 模拟服务返回一般错误。
*   **用户或编程常见错误:**  开发者需要正确处理 `hasPrivateToken()` 和 `hasRedemptionRecord()` 返回的 Promise，并根据不同的结果采取相应的操作。
*   **用户操作如何到达这里 (调试线索):**
    1. 网页的 JavaScript 代码调用了 `document.hasPrivateToken()` 或 `document.hasRedemptionRecord()` 方法来与 Trust Token 系统进行交互。
    2. Blink 引擎会与底层的 Trust Token 查询服务进行通信。
    3. 这些测试验证了 Blink 引擎在与 Trust Token 服务交互的不同情况下，API 的行为是否符合预期。

总而言之，这份代码片段专注于测试 `Document` 类的各种功能，涵盖了 DOM 操作、CSS 样式处理、JavaScript API 支持、页面生命周期管理以及与浏览器底层服务的交互。这些测试用例确保了 Blink 引擎的 `Document` 类能够正确地处理各种场景，为网页的正常渲染和功能运行提供了保障。

Prompt: 
```
这是目录为blink/renderer/core/dom/document_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
UpdatedCharacterDataRecords()[1]->node_);
  EXPECT_EQ(3u, observer.UpdatedCharacterDataRecords()[1]->offset_);
  EXPECT_EQ(4u, observer.UpdatedCharacterDataRecords()[1]->old_length_);
  EXPECT_EQ(0u, observer.UpdatedCharacterDataRecords()[1]->new_length_);

  insert_sample->insertData(3, "def", ASSERT_NO_EXCEPTION);
  ASSERT_EQ(3u, observer.UpdatedCharacterDataRecords().size());
  EXPECT_EQ(insert_sample, observer.UpdatedCharacterDataRecords()[2]->node_);
  EXPECT_EQ(3u, observer.UpdatedCharacterDataRecords()[2]->offset_);
  EXPECT_EQ(0u, observer.UpdatedCharacterDataRecords()[2]->old_length_);
  EXPECT_EQ(3u, observer.UpdatedCharacterDataRecords()[2]->new_length_);

  replace_sample->replaceData(6, 4, "ghi", ASSERT_NO_EXCEPTION);
  ASSERT_EQ(4u, observer.UpdatedCharacterDataRecords().size());
  EXPECT_EQ(replace_sample, observer.UpdatedCharacterDataRecords()[3]->node_);
  EXPECT_EQ(6u, observer.UpdatedCharacterDataRecords()[3]->offset_);
  EXPECT_EQ(4u, observer.UpdatedCharacterDataRecords()[3]->old_length_);
  EXPECT_EQ(3u, observer.UpdatedCharacterDataRecords()[3]->new_length_);
}

// This tests that meta-theme-color can be found correctly
TEST_F(DocumentTest, ThemeColor) {
  {
    SetHtmlInnerHTML(
        "<meta name=\"theme-color\" content=\"#00ff00\">"
        "<body>");
    EXPECT_EQ(Color(0, 255, 0), GetDocument().ThemeColor())
        << "Theme color should be bright green.";
  }

  {
    SetHtmlInnerHTML(
        "<body>"
        "<meta name=\"theme-color\" content=\"#00ff00\">");
    EXPECT_EQ(Color(0, 255, 0), GetDocument().ThemeColor())
        << "Theme color should be bright green.";
  }
}

TEST_F(DocumentTest, ValidationMessageCleanup) {
  ValidationMessageClient* original_client =
      &GetPage().GetValidationMessageClient();
  MockDocumentValidationMessageClient* mock_client =
      MakeGarbageCollected<MockDocumentValidationMessageClient>();
  GetDocument().GetSettings()->SetScriptEnabled(true);
  GetPage().SetValidationMessageClientForTesting(mock_client);
  // ImplicitOpen()-CancelParsing() makes Document.loadEventFinished()
  // true. It's necessary to kick unload process.
  GetDocument().ImplicitOpen(kForceSynchronousParsing);
  GetDocument().CancelParsing();
  GetDocument().AppendChild(
      GetDocument().CreateRawElement(html_names::kHTMLTag));
  SetHtmlInnerHTML("<body><input required></body>");
  Element* script = GetDocument().CreateRawElement(html_names::kScriptTag);
  script->setTextContent(
      "window.onunload = function() {"
      "document.querySelector('input').reportValidity(); };");
  GetDocument().body()->AppendChild(script);
  auto* input = To<HTMLInputElement>(GetDocument().body()->firstChild());
  DVLOG(0) << GetDocument().body()->outerHTML();

  // Sanity check.
  input->reportValidity();
  EXPECT_TRUE(mock_client->show_validation_message_was_called);
  mock_client->Reset();

  // DetachDocument() unloads the document, and shutdowns.
  GetDocument().GetFrame()->DetachDocument();
  EXPECT_TRUE(mock_client->document_detached_was_called);
  // Unload handler tried to show a validation message, but it should fail.
  EXPECT_FALSE(mock_client->show_validation_message_was_called);

  GetPage().SetValidationMessageClientForTesting(original_client);
}

// Verifies that calling EnsurePaintLocationDataValidForNode cleans compositor
// inputs only when necessary. We generally want to avoid cleaning the inputs,
// as it is more expensive than just doing layout.
TEST_F(DocumentTest,
       EnsurePaintLocationDataValidForNodeCompositingInputsOnlyWhenNecessary) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id='ancestor'>
      <div id='sticky' style='position:sticky;'>
        <div id='stickyChild'></div>
      </div>
      <div id='nonSticky'></div>
    </div>
  )HTML");
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_EQ(DocumentLifecycle::kStyleClean,
            GetDocument().Lifecycle().GetState());

  // Asking for any element that is not affected by a sticky element should only
  // advance the lifecycle to layout clean.
  GetDocument().EnsurePaintLocationDataValidForNode(
      GetDocument().getElementById(AtomicString("ancestor")),
      DocumentUpdateReason::kTest);
  EXPECT_EQ(DocumentLifecycle::kLayoutClean,
            GetDocument().Lifecycle().GetState());

  GetDocument().EnsurePaintLocationDataValidForNode(
      GetDocument().getElementById(AtomicString("nonSticky")),
      DocumentUpdateReason::kTest);
  EXPECT_EQ(DocumentLifecycle::kLayoutClean,
            GetDocument().Lifecycle().GetState());

  // However, asking for either the sticky element or it's descendents should
  // clean compositing inputs as well.
  GetDocument().EnsurePaintLocationDataValidForNode(
      GetDocument().getElementById(AtomicString("sticky")),
      DocumentUpdateReason::kTest);
  EXPECT_EQ(DocumentLifecycle::kLayoutClean,
            GetDocument().Lifecycle().GetState());

  // Dirty layout.
  GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                     AtomicString("background: red;"));
  EXPECT_EQ(DocumentLifecycle::kVisualUpdatePending,
            GetDocument().Lifecycle().GetState());

  GetDocument().EnsurePaintLocationDataValidForNode(
      GetDocument().getElementById(AtomicString("stickyChild")),
      DocumentUpdateReason::kTest);
  EXPECT_EQ(DocumentLifecycle::kLayoutClean,
            GetDocument().Lifecycle().GetState());
}

// Tests that the difference in computed style of direction on the html and body
// elements does not trigger a style recalc for viewport style propagation when
// the computed style for another element in the document is recalculated.
TEST_F(DocumentTest, ViewportPropagationNoRecalc) {
  SetHtmlInnerHTML(R"HTML(
    <body style='direction:rtl'>
      <div id=recalc></div>
    </body>
  )HTML");

  int old_element_count = GetDocument().GetStyleEngine().StyleForElementCount();

  Element* div = GetDocument().getElementById(AtomicString("recalc"));
  div->setAttribute(html_names::kStyleAttr, AtomicString("color:green"));
  GetDocument().UpdateStyleAndLayoutTree();

  int new_element_count = GetDocument().GetStyleEngine().StyleForElementCount();

  EXPECT_EQ(1, new_element_count - old_element_count);
}

// A relative url in a sandboxed, srcdoc frame should trigger a usecount.
TEST_F(DocumentTest, SandboxedSrcdocUserCounts_BasicRelativeUrl) {
  String base_url("https://example.com/");
  WebURL mocked_url = url_test_helpers::RegisterMockedURLLoadFromBase(
      base_url, test::CoreTestDataPath(), "white-1x1.png", "image/png");
  std::string content =
      R"(<html><body><img src='white-1x1.png'></body></html>)";
  NavigateSrcdocMaybeSandboxed(base_url, content, kIsSandboxed, kIsUseCounted);
  url_test_helpers::RegisterMockedURLUnregister(mocked_url);
}

// A relative url in a sandboxed, srcdoc frame should not trigger a usecount
// if the srcdoc document has defined a base element.
TEST_F(DocumentTest,
       SandboxedSrcdocUserCounts_BasicRelativeUrlWithBaseElement) {
  String base_url("https://example.com/");
  WebURL mocked_url = url_test_helpers::RegisterMockedURLLoadFromBase(
      base_url, test::CoreTestDataPath(), "white-1x1.png", "image/png");
  static constexpr char kSrcdocTemplate[] =
      R"(<html><head><base href='%s' /></head>
               <body><img src='white-1x1.png'></body></html>)";
  std::string content =
      base::StringPrintf(kSrcdocTemplate, base_url.Utf8().c_str());
  NavigateSrcdocMaybeSandboxed(base_url, content, kIsSandboxed,
                               kIsNotUseCounted);
  url_test_helpers::RegisterMockedURLUnregister(mocked_url);
}

// An absolute url in a sandboxed, srcdoc frame should not trigger a usecount.
TEST_F(DocumentTest, SandboxedSrcdocUserCounts_BasicAbsoluteUrl) {
  String base_url("https://example.com/");
  WebURL mocked_url = url_test_helpers::RegisterMockedURLLoadFromBase(
      base_url, test::CoreTestDataPath(), "white-1x1.png", "image/png");
  std::string content =
      R"(<html>
           <body>
             <img src='https://example.com/white-1x1.png'>
          </body>
        </html>)";
  NavigateSrcdocMaybeSandboxed(base_url, content, kIsSandboxed,
                               kIsNotUseCounted);
  url_test_helpers::RegisterMockedURLUnregister(mocked_url);
}

// As in BasicRelativeUrl, but this time the url is for an iframe.
TEST_F(DocumentTest, SandboxedSrcdocUserCounts_BasicRelativeUrlInIframe) {
  String base_url("https://example.com/");
  std::string content = R"(<html><body><iframe src='foo.html'></body></html>)";
  NavigateSrcdocMaybeSandboxed(base_url, content, kIsSandboxed, kIsUseCounted);
}

// Non-sandboxed srcdoc frames with relative urls shouldn't trigger the use
// count.
TEST_F(DocumentTest,
       SandboxedSrcdocUserCounts_BasicRelativeUrlInNonSandboxedIframe) {
  String base_url("https://example.com/");
  std::string content = R"(<html><body><iframe src='foo.html'></body></html>)";
  NavigateSrcdocMaybeSandboxed(base_url, content, kIsNotSandboxed,
                               kIsNotUseCounted);
}

// As in BasicAbsoluteUrl, but this time the url is for an iframe.
TEST_F(DocumentTest, SandboxedSrcdocUserCounts_BasicAbsoluteUrlInIframe) {
  String base_url("https://example.com/");
  std::string content =
      R"(<html>
           <body>
             <iframe src='https://example.com/foo.html'>
           </body>
         </html>)";
  NavigateSrcdocMaybeSandboxed(base_url, content, kIsSandboxed,
                               kIsNotUseCounted);
}

TEST_F(DocumentTest, CanExecuteScriptsWithSandboxAndIsolatedWorld) {
  NavigateWithSandbox(KURL("https://www.example.com/"));

  LocalFrame* frame = GetDocument().GetFrame();
  frame->GetSettings()->SetScriptEnabled(true);
  ScriptState* main_world_script_state = ToScriptStateForMainWorld(frame);
  v8::Isolate* isolate = main_world_script_state->GetIsolate();

  constexpr int kIsolatedWorldWithoutCSPId = 1;
  DOMWrapperWorld* world_without_csp =
      DOMWrapperWorld::EnsureIsolatedWorld(isolate, kIsolatedWorldWithoutCSPId);
  ScriptState* isolated_world_without_csp_script_state =
      ToScriptState(frame, *world_without_csp);
  ASSERT_TRUE(world_without_csp->IsIsolatedWorld());
  EXPECT_FALSE(IsolatedWorldCSP::Get().HasContentSecurityPolicy(
      kIsolatedWorldWithoutCSPId));

  constexpr int kIsolatedWorldWithCSPId = 2;
  DOMWrapperWorld* world_with_csp =
      DOMWrapperWorld::EnsureIsolatedWorld(isolate, kIsolatedWorldWithCSPId);
  IsolatedWorldCSP::Get().SetContentSecurityPolicy(
      kIsolatedWorldWithCSPId, String::FromUTF8("script-src *"),
      SecurityOrigin::Create(KURL("chrome-extension://123")));
  ScriptState* isolated_world_with_csp_script_state =
      ToScriptState(frame, *world_with_csp);
  ASSERT_TRUE(world_with_csp->IsIsolatedWorld());
  EXPECT_TRUE(IsolatedWorldCSP::Get().HasContentSecurityPolicy(
      kIsolatedWorldWithCSPId));

  {
    // Since the page is sandboxed, main world script execution shouldn't be
    // allowed.
    ScriptState::Scope scope(main_world_script_state);
    EXPECT_FALSE(frame->DomWindow()->CanExecuteScripts(kAboutToExecuteScript));
  }
  {
    // Isolated worlds without a dedicated CSP should also not be allowed to
    // run scripts.
    ScriptState::Scope scope(isolated_world_without_csp_script_state);
    EXPECT_FALSE(frame->DomWindow()->CanExecuteScripts(kAboutToExecuteScript));
  }
  {
    // An isolated world with a CSP should bypass the main world CSP, and be
    // able to run scripts.
    ScriptState::Scope scope(isolated_world_with_csp_script_state);
    EXPECT_TRUE(frame->DomWindow()->CanExecuteScripts(kAboutToExecuteScript));
  }
}

TEST_F(DocumentTest, ElementFromPointOnScrollbar) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  // This test requires that scrollbars take up space.
  ScopedMockOverlayScrollbars no_overlay_scrollbars(false);

  SetHtmlInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
    </style>
    <div id='content'>content</div>
  )HTML");

  // A hit test close to the bottom of the page without scrollbars should hit
  // the body element.
  EXPECT_EQ(GetDocument().ElementFromPoint(1, 590), GetDocument().body());

  // Add width which will cause a horizontal scrollbar.
  auto* content = GetDocument().getElementById(AtomicString("content"));
  content->setAttribute(html_names::kStyleAttr, AtomicString("width: 101%;"));

  // A hit test on the horizontal scrollbar should not return an element because
  // it is outside the viewport.
  EXPECT_EQ(GetDocument().ElementFromPoint(1, 590), nullptr);
  // A hit test above the horizontal scrollbar should hit the body element.
  EXPECT_EQ(GetDocument().ElementFromPoint(1, 580), GetDocument().body());
}

TEST_F(DocumentTest, ElementFromPointWithPageZoom) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  // This test requires that scrollbars take up space.
  ScopedMockOverlayScrollbars no_overlay_scrollbars(false);

  SetHtmlInnerHTML(R"HTML(
    <style>
      body { margin: 0; }
    </style>
    <div id='content' style='height: 10px;'>content</div>
  )HTML");

  // A hit test on the content div should hit it.
  auto* content = GetDocument().getElementById(AtomicString("content"));
  EXPECT_EQ(GetDocument().ElementFromPoint(1, 8), content);
  // A hit test below the content div should not hit it.
  EXPECT_EQ(GetDocument().ElementFromPoint(1, 12), GetDocument().body());

  // Zoom the page by 2x,
  GetDocument().GetFrame()->SetLayoutZoomFactor(2);

  // A hit test on the content div should hit it.
  EXPECT_EQ(GetDocument().ElementFromPoint(1, 8), content);
  // A hit test below the content div should not hit it.
  EXPECT_EQ(GetDocument().ElementFromPoint(1, 12), GetDocument().body());
}

TEST_F(DocumentTest, PrefersColorSchemeChanged) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);
  UpdateAllLifecyclePhasesForTest();

  auto* list = GetDocument().GetMediaQueryMatcher().MatchMedia(
      "(prefers-color-scheme: dark)");
  auto* listener = MakeGarbageCollected<PrefersColorSchemeTestListener>();
  list->AddListener(listener);

  EXPECT_FALSE(listener->IsNotified());

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);

  UpdateAllLifecyclePhasesForTest();
  PageAnimator::ServiceScriptedAnimations(
      base::TimeTicks(),
      {{GetDocument().GetScriptedAnimationController(), false}});

  EXPECT_TRUE(listener->IsNotified());
}

TEST_F(DocumentTest, FindInPageUkm) {
  ukm::TestAutoSetUkmRecorder recorder;

  EXPECT_EQ(recorder.entries_count(), 0u);
  GetDocument().MarkHasFindInPageRequest();
  EXPECT_EQ(recorder.entries_count(), 1u);
  GetDocument().MarkHasFindInPageRequest();
  EXPECT_EQ(recorder.entries_count(), 1u);

  auto entries = recorder.GetEntriesByName("Blink.FindInPage");
  EXPECT_EQ(entries.size(), 1u);
  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entries[0], "DidSearch"));
  EXPECT_EQ(*ukm::TestUkmRecorder::GetEntryMetric(entries[0], "DidSearch"), 1);
  EXPECT_FALSE(ukm::TestUkmRecorder::EntryHasMetric(
      entries[0], "DidHaveRenderSubtreeMatch"));

  GetDocument().MarkHasFindInPageContentVisibilityActiveMatch();
  EXPECT_EQ(recorder.entries_count(), 2u);
  GetDocument().MarkHasFindInPageContentVisibilityActiveMatch();
  EXPECT_EQ(recorder.entries_count(), 2u);
  entries = recorder.GetEntriesByName("Blink.FindInPage");
  EXPECT_EQ(entries.size(), 2u);

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entries[0], "DidSearch"));
  EXPECT_EQ(*ukm::TestUkmRecorder::GetEntryMetric(entries[0], "DidSearch"), 1);
  EXPECT_FALSE(ukm::TestUkmRecorder::EntryHasMetric(
      entries[0], "DidHaveRenderSubtreeMatch"));

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(
      entries[1], "DidHaveRenderSubtreeMatch"));
  EXPECT_EQ(*ukm::TestUkmRecorder::GetEntryMetric(entries[1],
                                                  "DidHaveRenderSubtreeMatch"),
            1);
  EXPECT_FALSE(ukm::TestUkmRecorder::EntryHasMetric(entries[1], "DidSearch"));
}

TEST_F(DocumentTest, FindInPageUkmInFrame) {
  std::string base_url = "http://internal.test/";

  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8("visible_iframe.html"));
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(base_url), test::CoreTestDataPath(),
      WebString::FromUTF8("single_iframe.html"));

  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl =
      web_view_helper.InitializeAndLoad(base_url + "single_iframe.html");

  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  Document* top_doc = web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();
  auto* iframe =
      To<HTMLIFrameElement>(top_doc->QuerySelector(AtomicString("iframe")));
  Document* document = iframe->contentDocument();
  ASSERT_TRUE(document);
  ASSERT_FALSE(document->IsInMainFrame());

  ukm::TestAutoSetUkmRecorder recorder;
  EXPECT_EQ(recorder.entries_count(), 0u);
  document->MarkHasFindInPageRequest();
  EXPECT_EQ(recorder.entries_count(), 1u);
  document->MarkHasFindInPageRequest();
  EXPECT_EQ(recorder.entries_count(), 1u);

  auto entries = recorder.GetEntriesByName("Blink.FindInPage");
  EXPECT_EQ(entries.size(), 1u);
  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entries[0], "DidSearch"));
  EXPECT_EQ(*ukm::TestUkmRecorder::GetEntryMetric(entries[0], "DidSearch"), 1);
  EXPECT_FALSE(ukm::TestUkmRecorder::EntryHasMetric(
      entries[0], "DidHaveRenderSubtreeMatch"));

  document->MarkHasFindInPageContentVisibilityActiveMatch();
  EXPECT_EQ(recorder.entries_count(), 2u);
  document->MarkHasFindInPageContentVisibilityActiveMatch();
  EXPECT_EQ(recorder.entries_count(), 2u);
  entries = recorder.GetEntriesByName("Blink.FindInPage");
  EXPECT_EQ(entries.size(), 2u);

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(entries[0], "DidSearch"));
  EXPECT_EQ(*ukm::TestUkmRecorder::GetEntryMetric(entries[0], "DidSearch"), 1);
  EXPECT_FALSE(ukm::TestUkmRecorder::EntryHasMetric(
      entries[0], "DidHaveRenderSubtreeMatch"));

  EXPECT_TRUE(ukm::TestUkmRecorder::EntryHasMetric(
      entries[1], "DidHaveRenderSubtreeMatch"));
  EXPECT_EQ(*ukm::TestUkmRecorder::GetEntryMetric(entries[1],
                                                  "DidHaveRenderSubtreeMatch"),
            1);
  EXPECT_FALSE(ukm::TestUkmRecorder::EntryHasMetric(entries[1], "DidSearch"));
}

TEST_F(DocumentTest, AtPageMarginWithDeviceScaleFactor) {
  GetDocument().GetFrame()->SetLayoutZoomFactor(2);
  SetBodyInnerHTML("<style>@page { margin: 50px; size: 400px 10in; }</style>");

  constexpr gfx::SizeF initial_page_size(800, 600);

  GetDocument().GetFrame()->StartPrinting(WebPrintParams(initial_page_size));
  GetDocument().View()->UpdateLifecyclePhasesForPrinting();

  WebPrintPageDescription description = GetDocument().GetPageDescription(0);

  EXPECT_EQ(50, description.margin_top);
  EXPECT_EQ(50, description.margin_right);
  EXPECT_EQ(50, description.margin_bottom);
  EXPECT_EQ(50, description.margin_left);
  EXPECT_EQ(gfx::SizeF(400, 960), description.size);
}

TEST_F(DocumentTest, HandlesDisconnectDuringHasPrivateToken) {
  // Check that a Mojo handle disconnecting during hasPrivateToken operation
  // execution results in the promise getting rejected with the proper
  // exception.
  V8TestingScope scope(KURL("https://trusttoken.example"));

  Document& document = scope.GetDocument();

  auto promise =
      document.hasPrivateToken(scope.GetScriptState(), "https://issuer.example",
                               scope.GetExceptionState());
  DocumentTest::SimulateTrustTokenQueryAnswererConnectionError(&document);
  ScriptPromiseTester promise_tester(scope.GetScriptState(), promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(scope.GetScriptState(), promise_tester.Value(),
                             DOMExceptionCode::kOperationError));
}

TEST_F(DocumentTest, RejectsHasPrivateTokenCallFromNonHttpNonHttpsDocument) {
  // Check that hasPrivateToken getting called from a secure, but
  // non-http/non-https, document results in an exception being thrown.
  V8TestingScope scope(KURL("file:///trusttoken.txt"));

  Document& document = scope.GetDocument();
  ScriptState* script_state = scope.GetScriptState();
  DummyExceptionStateForTesting exception_state;

  auto promise = document.hasPrivateToken(
      script_state, "https://issuer.example", exception_state);
  EXPECT_TRUE(promise.IsEmpty());
  EXPECT_TRUE(exception_state.HadException());
  EXPECT_EQ(exception_state.CodeAs<DOMExceptionCode>(),
            DOMExceptionCode::kNotAllowedError);
}

namespace {
class MockTrustTokenQueryAnswerer
    : public network::mojom::blink::TrustTokenQueryAnswerer {
 public:
  enum Outcome { kError, kInvalidArgument, kResourceExhausted, kTrue, kFalse };
  explicit MockTrustTokenQueryAnswerer(Outcome outcome) : outcome_(outcome) {}

  void HasTrustTokens(
      const ::scoped_refptr<const ::blink::SecurityOrigin>& issuer,
      HasTrustTokensCallback callback) override {
    auto result = network::mojom::blink::HasTrustTokensResult::New();
    result->status = network::mojom::blink::TrustTokenOperationStatus::kOk;
    switch (outcome_) {
      case kTrue: {
        result->has_trust_tokens = true;
        std::move(callback).Run(std::move(result));
        return;
      }
      case kFalse: {
        result->has_trust_tokens = false;
        std::move(callback).Run(std::move(result));
        return;
      }
      case kInvalidArgument: {
        result->status =
            network::mojom::blink::TrustTokenOperationStatus::kInvalidArgument;
        std::move(callback).Run(std::move(result));
        return;
      }
      case kResourceExhausted: {
        result->status = network::mojom::blink::TrustTokenOperationStatus::
            kResourceExhausted;
        std::move(callback).Run(std::move(result));
        return;
      }
      case kError: {
        result->status =
            network::mojom::blink::TrustTokenOperationStatus::kUnknownError;
        std::move(callback).Run(std::move(result));
      }
    }
  }

  void HasRedemptionRecord(
      const ::scoped_refptr<const ::blink::SecurityOrigin>& issuer,
      HasRedemptionRecordCallback callback) override {
    auto result = network::mojom::blink::HasRedemptionRecordResult::New();
    result->status = network::mojom::blink::TrustTokenOperationStatus::kOk;
    switch (outcome_) {
      case kTrue: {
        result->has_redemption_record = true;
        break;
      }
      case kFalse: {
        result->has_redemption_record = false;
        break;
      }
      case kInvalidArgument: {
        result->status =
            network::mojom::blink::TrustTokenOperationStatus::kInvalidArgument;
        break;
      }
      case kResourceExhausted: {
        result->status = network::mojom::blink::TrustTokenOperationStatus::
            kResourceExhausted;
        break;
      }
      case kError: {
        result->status =
            network::mojom::blink::TrustTokenOperationStatus::kUnknownError;
        break;
      }
    }
    std::move(callback).Run(std::move(result));
  }

  void Bind(mojo::ScopedMessagePipeHandle handle) {
    receiver_.Bind(
        mojo::PendingReceiver<network::mojom::blink::TrustTokenQueryAnswerer>(
            std::move(handle)));
  }

 private:
  Outcome outcome_;
  mojo::Receiver<network::mojom::blink::TrustTokenQueryAnswerer> receiver_{
      this};
};
}  // namespace

TEST_F(DocumentTest, HasPrivateTokenSuccess) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(MockTrustTokenQueryAnswerer::kTrue);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                         WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasPrivateToken");

  auto promise = document.hasPrivateToken(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());
  EXPECT_TRUE(promise_tester.Value().V8Value()->IsTrue());

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HasPrivateTokenSuccessWithFalseValue) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(MockTrustTokenQueryAnswerer::kFalse);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                         WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasPrivateToken");

  auto promise = document.hasPrivateToken(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());
  EXPECT_TRUE(promise_tester.Value().V8Value()->IsFalse());

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HasPrivateTokenOperationError) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(MockTrustTokenQueryAnswerer::kError);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                         WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasPrivateToken");

  auto promise = document.hasPrivateToken(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(script_state, promise_tester.Value(),
                             DOMExceptionCode::kOperationError));

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HasPrivateTokenInvalidArgument) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(
      MockTrustTokenQueryAnswerer::kInvalidArgument);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                         WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasPrivateToken");

  auto promise = document.hasPrivateToken(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(script_state, promise_tester.Value(),
                             DOMExceptionCode::kOperationError));

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HasPrivateTokenResourceExhausted) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(
      MockTrustTokenQueryAnswerer::kResourceExhausted);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                         WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasPrivateToken");

  auto promise = document.hasPrivateToken(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsRejected());
  EXPECT_TRUE(IsDOMException(script_state, promise_tester.Value(),
                             DOMExceptionCode::kOperationError));

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HasRedemptionRecordSuccess) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(MockTrustTokenQueryAnswerer::kTrue);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                         WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasRedemptionRecord");

  auto promise = document.hasRedemptionRecord(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());
  EXPECT_TRUE(promise_tester.Value().V8Value()->IsTrue());

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HasRedemptionRecordSuccessWithFalseValue) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(MockTrustTokenQueryAnswerer::kFalse);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                         WTF::Unretained(&answerer)));

  ScriptState* script_state = scope.GetScriptState();
  ExceptionState exception_state(script_state->GetIsolate(),
                                 v8::ExceptionContext::kOperation, "Document",
                                 "hasRedemptionRecord");

  auto promise = document.hasRedemptionRecord(
      script_state, "https://issuer.example", exception_state);

  ScriptPromiseTester promise_tester(script_state, promise);
  promise_tester.WaitUntilSettled();
  EXPECT_TRUE(promise_tester.IsFulfilled());
  EXPECT_TRUE(promise_tester.Value().V8Value()->IsFalse());

  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_, {});
}

TEST_F(DocumentTest, HasRedemptionRecordOperationError) {
  V8TestingScope scope(KURL("https://secure.example"));

  MockTrustTokenQueryAnswerer answerer(MockTrustTokenQueryAnswerer::kError);

  Document& document = scope.GetDocument();
  document.GetFrame()->GetBrowserInterfaceBroker().SetBinderForTesting(
      network::mojom::blink::TrustTokenQueryAnswerer::Name_,
      WTF::BindRepeating(&MockTrustTokenQueryAnswerer::Bind,
                        
"""


```