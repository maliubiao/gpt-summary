Response:
Let's break down the thought process to answer the request about the provided C++ code snippet.

**1. Understanding the Goal:**

The core request is to analyze a snippet of C++ code within the context of Chromium's Blink rendering engine and the `v8_compile_hints_producer.cc` file. Specifically, we need to figure out what this code *does*, how it relates to web technologies (JavaScript, HTML, CSS), common errors, debugging, and finally, summarize its function.

**2. Initial Code Examination - Pattern Recognition:**

The first thing that jumps out is the repetitive nature of the code. It's a long sequence of `.SetDataXXX()` calls, where XXX is an incrementing number, and each call takes data from a `raw_data` array. The data is being combined using bitwise left shift (`<< 32`) and bitwise OR (`|`), indicating that two adjacent bytes from `raw_data` are being combined into a 64-bit integer.

**3. Hypothesizing the Purpose:**

Given the filename `v8_compile_hints_producer.cc`, and the association of V8 with JavaScript compilation in Chromium, a likely hypothesis is that this code is involved in generating "hints" for the V8 JavaScript engine to optimize compilation. These hints would likely contain pre-computed data or metadata about the JavaScript code being executed.

The repetitive `SetDataXXX()` pattern suggests that these hints are being stored in a structured way, perhaps in an object or data structure. The sheer number of `SetData` calls and the incrementing index hints at a large amount of data being processed.

**4. Connecting to Web Technologies:**

* **JavaScript:** The most direct connection is through the V8 engine. Compile hints are designed to improve the performance of JavaScript code execution.
* **HTML:** HTML loading and parsing often trigger JavaScript execution. The hints could be generated based on the HTML structure or the JavaScript embedded within it.
* **CSS:** While less direct, CSS can indirectly influence JavaScript performance by triggering layout and rendering, which in turn might affect JavaScript execution patterns. However, it's less likely that compile hints would directly be derived from CSS in this specific context. The hints are more about *how* the JavaScript runs, not necessarily *what* it manipulates visually.

**5. Reasoning about Input and Output:**

* **Input:** The code clearly takes a `raw_data` array as input. The indices suggest it's an array of bytes.
* **Output:** The `.SetDataXXX()` calls suggest the output is an object or a builder pattern where properties are being set sequentially. The return type of these `SetData` methods seems to be the object itself, allowing for method chaining. The final output would likely be the fully populated object containing the extracted data.

**6. Identifying Potential User/Programming Errors:**

* **Incorrect `raw_data` size:**  A common error would be providing a `raw_data` array that is too small. This would lead to out-of-bounds access and crashes.
* **Incorrect data format:** If the `raw_data` doesn't conform to the expected format (e.g., not a sequence of bytes in the expected order), the resulting compile hints would be incorrect or garbage.
* **Logic errors in the data extraction:** Although the provided code is straightforward, there's always a possibility of an off-by-one error or incorrect bit manipulation if the logic were more complex.

**7. Tracing User Actions (Debugging Clues):**

To reach this code, a user would likely:

1. **Load a webpage:** This is the initial trigger for the rendering engine.
2. **The page contains JavaScript:** The presence of JavaScript is what necessitates the V8 engine's involvement.
3. **V8 starts compiling the JavaScript:**  This is the point where compile hints become relevant. The `V8CompileHintsProducer` would be invoked as part of the compilation pipeline.
4. **The specific conditions for generating *these particular* hints are met:** This is the most crucial and opaque part. It depends on what kind of hints this producer is responsible for. It could be triggered by specific JavaScript language features, code patterns, or even characteristics of the loaded webpage.

**8. Focusing on the Provided Snippet:**

The provided snippet *specifically* deals with taking a byte array and populating a large number of 64-bit integer fields in some object. It doesn't reveal *why* this data is important or what it represents.

**9. Answering the Specific Questions and Structuring the Response:**

Now, it's time to structure the findings and address each point in the prompt systematically. This involves summarizing the hypothesized functionality, explaining the connections to web technologies with examples, detailing the assumed input and output, describing potential errors, outlining the user actions leading to this code, and finally, providing a concise summary of the code's function within the larger context.

**Self-Correction/Refinement during the Process:**

Initially, I might have overemphasized the direct influence of CSS on compile hints. However, recognizing that compile hints are more focused on JavaScript execution characteristics led to a more accurate assessment. Similarly, while HTML triggers JavaScript, the direct link in this code snippet is the *compiled JavaScript code* itself, or some metadata derived from it. The raw data is likely a pre-existing structure, not something dynamically generated directly from HTML at this step. The process of generating this `raw_data` is outside the scope of the provided snippet.
好的，让我们来分析一下这段代码片段的功能。

**功能归纳：**

这段代码的主要功能是从一个名为 `raw_data` 的字节数组中，连续读取多个（从索引 656 到 1499）双字节的数据，并将这些数据以 64 位整数的形式设置到某个对象（或构建器）的连续编号的属性中，属性名从 `Data328` 一直递增到 `Data749`。

**与 JavaScript, HTML, CSS 的关系：**

这段代码位于 `blink/renderer/bindings/core/v8` 目录下，表明它与 Blink 渲染引擎和 V8 JavaScript 引擎的绑定有关。更具体地说，它在 `v8_compile_hints_producer.cc` 文件中，暗示它与为 V8 编译过程生成 "提示" (hints) 有关。

这些编译提示是为了帮助 V8 引擎更高效地编译和优化 JavaScript 代码。虽然这段代码本身不直接操作 JavaScript、HTML 或 CSS 的语法结构，但它处理的数据很可能是从这些资源中提取或计算出来的，用于指导 V8 的编译决策。

**举例说明：**

假设 `raw_data` 数组包含了从解析 JavaScript 代码中提取出的某些特征信息。例如，这些信息可能包括：

* **函数调用的频率和类型：**  V8 可以根据这些提示，对频繁调用的函数进行更激进的优化。
* **对象属性的访问模式：**  提示可以指示哪些属性经常被访问，以及访问的类型（读取、写入）。
* **数据类型的推断信息：**  帮助 V8 更准确地推断变量的类型，从而进行更有效的编译。

**假设输入与输出：**

* **假设输入 (`raw_data`)：** 一个包含足够字节的 `unsigned char` 数组，其中索引 656 到 1499 的位置存储着需要提取的编译提示数据。每两个字节组成一个需要被解析为 64 位整数的数据单元。

* **假设输出：**  一个对象，该对象拥有从 `Data328` 到 `Data749` 的一系列 `int64_t` 类型的属性，这些属性的值分别对应从 `raw_data` 中提取并组合得到的 64 位整数。  由于代码使用了链式调用 (`.SetDataXXX(...)`),  可以推测这些 `SetData` 方法返回的是对象自身的引用。

**用户或编程常见的使用错误：**

* **`raw_data` 数组大小不足：** 如果 `raw_data` 数组的大小小于 1500 (因为访问到了索引 1499)，则会导致数组越界访问，程序崩溃。这是一个非常典型的编程错误。

   ```c++
   // 错误示例：raw_data 大小不足
   unsigned char raw_data[1000];
   // ... 尝试执行上述代码片段会导致越界访问
   ```

* **数据类型不匹配：** 虽然代码将读取到的两个字节强制转换为 `int64_t`，但如果 `raw_data` 中存储的数据并非预期格式，例如存储的是字符数据而不是代表数值的信息，那么生成的编译提示将是无意义的，可能导致 V8 的优化失败或产生错误的行为。

* **索引计算错误：**  尽管这段代码的索引是连续的，但在更复杂的场景中，计算 `raw_data` 中数据的起始索引和长度时可能会出现错误，导致读取到错误的数据。

**用户操作如何一步步的到达这里（调试线索）：**

1. **用户在浏览器中加载一个包含 JavaScript 代码的网页。**
2. **Blink 渲染引擎开始解析 HTML、CSS 和 JavaScript 代码。**
3. **当 V8 引擎需要编译 JavaScript 代码时，Blink 会调用 `V8CompileHintsProducer` 来生成编译提示。**
4. **作为生成提示的一部分，可能需要从某些中间表示或缓存的数据中读取原始数据（即这里的 `raw_data`）。**
5. **这段代码负责将 `raw_data` 中特定偏移量的数据提取出来，并设置到用于传递给 V8 的编译提示对象中。**

**作为调试线索：** 如果在 V8 编译 JavaScript 代码时出现性能问题或错误，开发人员可能会检查与编译提示相关的代码。如果怀疑是某些特定的提示数据导致了问题，他们可能会：

* **设置断点在 `SetDataXXX` 调用处，查看 `raw_data` 的内容和即将设置的值。**
* **追踪 `raw_data` 的来源，了解这些数据是如何生成的。**
* **分析 V8 的编译日志，查看这些提示是否被正确使用，以及是否产生了预期的优化效果。**

**第 2 部分功能归纳：**

这段代码片段是 `v8_compile_hints_producer.cc` 文件中负责提取大量原始字节数据并将其转换为结构化编译提示信息的一部分。它专注于从 `raw_data` 数组的特定区域（索引 656 到 1499）读取双字节数据，并将这些数据组合成 64 位整数，然后将这些整数分别设置到目标对象的 `Data328` 到 `Data749` 属性中。这个过程是为 V8 JavaScript 引擎的编译优化提供信息支持的关键步骤。

### 提示词
```
这是目录为blink/renderer/bindings/core/v8/v8_compile_hints_producer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
<< 32 | raw_data[658])
      .SetData330(static_cast<int64_t>(raw_data[661]) << 32 | raw_data[660])
      .SetData331(static_cast<int64_t>(raw_data[663]) << 32 | raw_data[662])
      .SetData332(static_cast<int64_t>(raw_data[665]) << 32 | raw_data[664])
      .SetData333(static_cast<int64_t>(raw_data[667]) << 32 | raw_data[666])
      .SetData334(static_cast<int64_t>(raw_data[669]) << 32 | raw_data[668])
      .SetData335(static_cast<int64_t>(raw_data[671]) << 32 | raw_data[670])
      .SetData336(static_cast<int64_t>(raw_data[673]) << 32 | raw_data[672])
      .SetData337(static_cast<int64_t>(raw_data[675]) << 32 | raw_data[674])
      .SetData338(static_cast<int64_t>(raw_data[677]) << 32 | raw_data[676])
      .SetData339(static_cast<int64_t>(raw_data[679]) << 32 | raw_data[678])
      .SetData340(static_cast<int64_t>(raw_data[681]) << 32 | raw_data[680])
      .SetData341(static_cast<int64_t>(raw_data[683]) << 32 | raw_data[682])
      .SetData342(static_cast<int64_t>(raw_data[685]) << 32 | raw_data[684])
      .SetData343(static_cast<int64_t>(raw_data[687]) << 32 | raw_data[686])
      .SetData344(static_cast<int64_t>(raw_data[689]) << 32 | raw_data[688])
      .SetData345(static_cast<int64_t>(raw_data[691]) << 32 | raw_data[690])
      .SetData346(static_cast<int64_t>(raw_data[693]) << 32 | raw_data[692])
      .SetData347(static_cast<int64_t>(raw_data[695]) << 32 | raw_data[694])
      .SetData348(static_cast<int64_t>(raw_data[697]) << 32 | raw_data[696])
      .SetData349(static_cast<int64_t>(raw_data[699]) << 32 | raw_data[698])
      .SetData350(static_cast<int64_t>(raw_data[701]) << 32 | raw_data[700])
      .SetData351(static_cast<int64_t>(raw_data[703]) << 32 | raw_data[702])
      .SetData352(static_cast<int64_t>(raw_data[705]) << 32 | raw_data[704])
      .SetData353(static_cast<int64_t>(raw_data[707]) << 32 | raw_data[706])
      .SetData354(static_cast<int64_t>(raw_data[709]) << 32 | raw_data[708])
      .SetData355(static_cast<int64_t>(raw_data[711]) << 32 | raw_data[710])
      .SetData356(static_cast<int64_t>(raw_data[713]) << 32 | raw_data[712])
      .SetData357(static_cast<int64_t>(raw_data[715]) << 32 | raw_data[714])
      .SetData358(static_cast<int64_t>(raw_data[717]) << 32 | raw_data[716])
      .SetData359(static_cast<int64_t>(raw_data[719]) << 32 | raw_data[718])
      .SetData360(static_cast<int64_t>(raw_data[721]) << 32 | raw_data[720])
      .SetData361(static_cast<int64_t>(raw_data[723]) << 32 | raw_data[722])
      .SetData362(static_cast<int64_t>(raw_data[725]) << 32 | raw_data[724])
      .SetData363(static_cast<int64_t>(raw_data[727]) << 32 | raw_data[726])
      .SetData364(static_cast<int64_t>(raw_data[729]) << 32 | raw_data[728])
      .SetData365(static_cast<int64_t>(raw_data[731]) << 32 | raw_data[730])
      .SetData366(static_cast<int64_t>(raw_data[733]) << 32 | raw_data[732])
      .SetData367(static_cast<int64_t>(raw_data[735]) << 32 | raw_data[734])
      .SetData368(static_cast<int64_t>(raw_data[737]) << 32 | raw_data[736])
      .SetData369(static_cast<int64_t>(raw_data[739]) << 32 | raw_data[738])
      .SetData370(static_cast<int64_t>(raw_data[741]) << 32 | raw_data[740])
      .SetData371(static_cast<int64_t>(raw_data[743]) << 32 | raw_data[742])
      .SetData372(static_cast<int64_t>(raw_data[745]) << 32 | raw_data[744])
      .SetData373(static_cast<int64_t>(raw_data[747]) << 32 | raw_data[746])
      .SetData374(static_cast<int64_t>(raw_data[749]) << 32 | raw_data[748])
      .SetData375(static_cast<int64_t>(raw_data[751]) << 32 | raw_data[750])
      .SetData376(static_cast<int64_t>(raw_data[753]) << 32 | raw_data[752])
      .SetData377(static_cast<int64_t>(raw_data[755]) << 32 | raw_data[754])
      .SetData378(static_cast<int64_t>(raw_data[757]) << 32 | raw_data[756])
      .SetData379(static_cast<int64_t>(raw_data[759]) << 32 | raw_data[758])
      .SetData380(static_cast<int64_t>(raw_data[761]) << 32 | raw_data[760])
      .SetData381(static_cast<int64_t>(raw_data[763]) << 32 | raw_data[762])
      .SetData382(static_cast<int64_t>(raw_data[765]) << 32 | raw_data[764])
      .SetData383(static_cast<int64_t>(raw_data[767]) << 32 | raw_data[766])
      .SetData384(static_cast<int64_t>(raw_data[769]) << 32 | raw_data[768])
      .SetData385(static_cast<int64_t>(raw_data[771]) << 32 | raw_data[770])
      .SetData386(static_cast<int64_t>(raw_data[773]) << 32 | raw_data[772])
      .SetData387(static_cast<int64_t>(raw_data[775]) << 32 | raw_data[774])
      .SetData388(static_cast<int64_t>(raw_data[777]) << 32 | raw_data[776])
      .SetData389(static_cast<int64_t>(raw_data[779]) << 32 | raw_data[778])
      .SetData390(static_cast<int64_t>(raw_data[781]) << 32 | raw_data[780])
      .SetData391(static_cast<int64_t>(raw_data[783]) << 32 | raw_data[782])
      .SetData392(static_cast<int64_t>(raw_data[785]) << 32 | raw_data[784])
      .SetData393(static_cast<int64_t>(raw_data[787]) << 32 | raw_data[786])
      .SetData394(static_cast<int64_t>(raw_data[789]) << 32 | raw_data[788])
      .SetData395(static_cast<int64_t>(raw_data[791]) << 32 | raw_data[790])
      .SetData396(static_cast<int64_t>(raw_data[793]) << 32 | raw_data[792])
      .SetData397(static_cast<int64_t>(raw_data[795]) << 32 | raw_data[794])
      .SetData398(static_cast<int64_t>(raw_data[797]) << 32 | raw_data[796])
      .SetData399(static_cast<int64_t>(raw_data[799]) << 32 | raw_data[798])
      .SetData400(static_cast<int64_t>(raw_data[801]) << 32 | raw_data[800])
      .SetData401(static_cast<int64_t>(raw_data[803]) << 32 | raw_data[802])
      .SetData402(static_cast<int64_t>(raw_data[805]) << 32 | raw_data[804])
      .SetData403(static_cast<int64_t>(raw_data[807]) << 32 | raw_data[806])
      .SetData404(static_cast<int64_t>(raw_data[809]) << 32 | raw_data[808])
      .SetData405(static_cast<int64_t>(raw_data[811]) << 32 | raw_data[810])
      .SetData406(static_cast<int64_t>(raw_data[813]) << 32 | raw_data[812])
      .SetData407(static_cast<int64_t>(raw_data[815]) << 32 | raw_data[814])
      .SetData408(static_cast<int64_t>(raw_data[817]) << 32 | raw_data[816])
      .SetData409(static_cast<int64_t>(raw_data[819]) << 32 | raw_data[818])
      .SetData410(static_cast<int64_t>(raw_data[821]) << 32 | raw_data[820])
      .SetData411(static_cast<int64_t>(raw_data[823]) << 32 | raw_data[822])
      .SetData412(static_cast<int64_t>(raw_data[825]) << 32 | raw_data[824])
      .SetData413(static_cast<int64_t>(raw_data[827]) << 32 | raw_data[826])
      .SetData414(static_cast<int64_t>(raw_data[829]) << 32 | raw_data[828])
      .SetData415(static_cast<int64_t>(raw_data[831]) << 32 | raw_data[830])
      .SetData416(static_cast<int64_t>(raw_data[833]) << 32 | raw_data[832])
      .SetData417(static_cast<int64_t>(raw_data[835]) << 32 | raw_data[834])
      .SetData418(static_cast<int64_t>(raw_data[837]) << 32 | raw_data[836])
      .SetData419(static_cast<int64_t>(raw_data[839]) << 32 | raw_data[838])
      .SetData420(static_cast<int64_t>(raw_data[841]) << 32 | raw_data[840])
      .SetData421(static_cast<int64_t>(raw_data[843]) << 32 | raw_data[842])
      .SetData422(static_cast<int64_t>(raw_data[845]) << 32 | raw_data[844])
      .SetData423(static_cast<int64_t>(raw_data[847]) << 32 | raw_data[846])
      .SetData424(static_cast<int64_t>(raw_data[849]) << 32 | raw_data[848])
      .SetData425(static_cast<int64_t>(raw_data[851]) << 32 | raw_data[850])
      .SetData426(static_cast<int64_t>(raw_data[853]) << 32 | raw_data[852])
      .SetData427(static_cast<int64_t>(raw_data[855]) << 32 | raw_data[854])
      .SetData428(static_cast<int64_t>(raw_data[857]) << 32 | raw_data[856])
      .SetData429(static_cast<int64_t>(raw_data[859]) << 32 | raw_data[858])
      .SetData430(static_cast<int64_t>(raw_data[861]) << 32 | raw_data[860])
      .SetData431(static_cast<int64_t>(raw_data[863]) << 32 | raw_data[862])
      .SetData432(static_cast<int64_t>(raw_data[865]) << 32 | raw_data[864])
      .SetData433(static_cast<int64_t>(raw_data[867]) << 32 | raw_data[866])
      .SetData434(static_cast<int64_t>(raw_data[869]) << 32 | raw_data[868])
      .SetData435(static_cast<int64_t>(raw_data[871]) << 32 | raw_data[870])
      .SetData436(static_cast<int64_t>(raw_data[873]) << 32 | raw_data[872])
      .SetData437(static_cast<int64_t>(raw_data[875]) << 32 | raw_data[874])
      .SetData438(static_cast<int64_t>(raw_data[877]) << 32 | raw_data[876])
      .SetData439(static_cast<int64_t>(raw_data[879]) << 32 | raw_data[878])
      .SetData440(static_cast<int64_t>(raw_data[881]) << 32 | raw_data[880])
      .SetData441(static_cast<int64_t>(raw_data[883]) << 32 | raw_data[882])
      .SetData442(static_cast<int64_t>(raw_data[885]) << 32 | raw_data[884])
      .SetData443(static_cast<int64_t>(raw_data[887]) << 32 | raw_data[886])
      .SetData444(static_cast<int64_t>(raw_data[889]) << 32 | raw_data[888])
      .SetData445(static_cast<int64_t>(raw_data[891]) << 32 | raw_data[890])
      .SetData446(static_cast<int64_t>(raw_data[893]) << 32 | raw_data[892])
      .SetData447(static_cast<int64_t>(raw_data[895]) << 32 | raw_data[894])
      .SetData448(static_cast<int64_t>(raw_data[897]) << 32 | raw_data[896])
      .SetData449(static_cast<int64_t>(raw_data[899]) << 32 | raw_data[898])
      .SetData450(static_cast<int64_t>(raw_data[901]) << 32 | raw_data[900])
      .SetData451(static_cast<int64_t>(raw_data[903]) << 32 | raw_data[902])
      .SetData452(static_cast<int64_t>(raw_data[905]) << 32 | raw_data[904])
      .SetData453(static_cast<int64_t>(raw_data[907]) << 32 | raw_data[906])
      .SetData454(static_cast<int64_t>(raw_data[909]) << 32 | raw_data[908])
      .SetData455(static_cast<int64_t>(raw_data[911]) << 32 | raw_data[910])
      .SetData456(static_cast<int64_t>(raw_data[913]) << 32 | raw_data[912])
      .SetData457(static_cast<int64_t>(raw_data[915]) << 32 | raw_data[914])
      .SetData458(static_cast<int64_t>(raw_data[917]) << 32 | raw_data[916])
      .SetData459(static_cast<int64_t>(raw_data[919]) << 32 | raw_data[918])
      .SetData460(static_cast<int64_t>(raw_data[921]) << 32 | raw_data[920])
      .SetData461(static_cast<int64_t>(raw_data[923]) << 32 | raw_data[922])
      .SetData462(static_cast<int64_t>(raw_data[925]) << 32 | raw_data[924])
      .SetData463(static_cast<int64_t>(raw_data[927]) << 32 | raw_data[926])
      .SetData464(static_cast<int64_t>(raw_data[929]) << 32 | raw_data[928])
      .SetData465(static_cast<int64_t>(raw_data[931]) << 32 | raw_data[930])
      .SetData466(static_cast<int64_t>(raw_data[933]) << 32 | raw_data[932])
      .SetData467(static_cast<int64_t>(raw_data[935]) << 32 | raw_data[934])
      .SetData468(static_cast<int64_t>(raw_data[937]) << 32 | raw_data[936])
      .SetData469(static_cast<int64_t>(raw_data[939]) << 32 | raw_data[938])
      .SetData470(static_cast<int64_t>(raw_data[941]) << 32 | raw_data[940])
      .SetData471(static_cast<int64_t>(raw_data[943]) << 32 | raw_data[942])
      .SetData472(static_cast<int64_t>(raw_data[945]) << 32 | raw_data[944])
      .SetData473(static_cast<int64_t>(raw_data[947]) << 32 | raw_data[946])
      .SetData474(static_cast<int64_t>(raw_data[949]) << 32 | raw_data[948])
      .SetData475(static_cast<int64_t>(raw_data[951]) << 32 | raw_data[950])
      .SetData476(static_cast<int64_t>(raw_data[953]) << 32 | raw_data[952])
      .SetData477(static_cast<int64_t>(raw_data[955]) << 32 | raw_data[954])
      .SetData478(static_cast<int64_t>(raw_data[957]) << 32 | raw_data[956])
      .SetData479(static_cast<int64_t>(raw_data[959]) << 32 | raw_data[958])
      .SetData480(static_cast<int64_t>(raw_data[961]) << 32 | raw_data[960])
      .SetData481(static_cast<int64_t>(raw_data[963]) << 32 | raw_data[962])
      .SetData482(static_cast<int64_t>(raw_data[965]) << 32 | raw_data[964])
      .SetData483(static_cast<int64_t>(raw_data[967]) << 32 | raw_data[966])
      .SetData484(static_cast<int64_t>(raw_data[969]) << 32 | raw_data[968])
      .SetData485(static_cast<int64_t>(raw_data[971]) << 32 | raw_data[970])
      .SetData486(static_cast<int64_t>(raw_data[973]) << 32 | raw_data[972])
      .SetData487(static_cast<int64_t>(raw_data[975]) << 32 | raw_data[974])
      .SetData488(static_cast<int64_t>(raw_data[977]) << 32 | raw_data[976])
      .SetData489(static_cast<int64_t>(raw_data[979]) << 32 | raw_data[978])
      .SetData490(static_cast<int64_t>(raw_data[981]) << 32 | raw_data[980])
      .SetData491(static_cast<int64_t>(raw_data[983]) << 32 | raw_data[982])
      .SetData492(static_cast<int64_t>(raw_data[985]) << 32 | raw_data[984])
      .SetData493(static_cast<int64_t>(raw_data[987]) << 32 | raw_data[986])
      .SetData494(static_cast<int64_t>(raw_data[989]) << 32 | raw_data[988])
      .SetData495(static_cast<int64_t>(raw_data[991]) << 32 | raw_data[990])
      .SetData496(static_cast<int64_t>(raw_data[993]) << 32 | raw_data[992])
      .SetData497(static_cast<int64_t>(raw_data[995]) << 32 | raw_data[994])
      .SetData498(static_cast<int64_t>(raw_data[997]) << 32 | raw_data[996])
      .SetData499(static_cast<int64_t>(raw_data[999]) << 32 | raw_data[998])
      .SetData500(static_cast<int64_t>(raw_data[1001]) << 32 | raw_data[1000])
      .SetData501(static_cast<int64_t>(raw_data[1003]) << 32 | raw_data[1002])
      .SetData502(static_cast<int64_t>(raw_data[1005]) << 32 | raw_data[1004])
      .SetData503(static_cast<int64_t>(raw_data[1007]) << 32 | raw_data[1006])
      .SetData504(static_cast<int64_t>(raw_data[1009]) << 32 | raw_data[1008])
      .SetData505(static_cast<int64_t>(raw_data[1011]) << 32 | raw_data[1010])
      .SetData506(static_cast<int64_t>(raw_data[1013]) << 32 | raw_data[1012])
      .SetData507(static_cast<int64_t>(raw_data[1015]) << 32 | raw_data[1014])
      .SetData508(static_cast<int64_t>(raw_data[1017]) << 32 | raw_data[1016])
      .SetData509(static_cast<int64_t>(raw_data[1019]) << 32 | raw_data[1018])
      .SetData510(static_cast<int64_t>(raw_data[1021]) << 32 | raw_data[1020])
      .SetData511(static_cast<int64_t>(raw_data[1023]) << 32 | raw_data[1022])
      .SetData512(static_cast<int64_t>(raw_data[1025]) << 32 | raw_data[1024])
      .SetData513(static_cast<int64_t>(raw_data[1027]) << 32 | raw_data[1026])
      .SetData514(static_cast<int64_t>(raw_data[1029]) << 32 | raw_data[1028])
      .SetData515(static_cast<int64_t>(raw_data[1031]) << 32 | raw_data[1030])
      .SetData516(static_cast<int64_t>(raw_data[1033]) << 32 | raw_data[1032])
      .SetData517(static_cast<int64_t>(raw_data[1035]) << 32 | raw_data[1034])
      .SetData518(static_cast<int64_t>(raw_data[1037]) << 32 | raw_data[1036])
      .SetData519(static_cast<int64_t>(raw_data[1039]) << 32 | raw_data[1038])
      .SetData520(static_cast<int64_t>(raw_data[1041]) << 32 | raw_data[1040])
      .SetData521(static_cast<int64_t>(raw_data[1043]) << 32 | raw_data[1042])
      .SetData522(static_cast<int64_t>(raw_data[1045]) << 32 | raw_data[1044])
      .SetData523(static_cast<int64_t>(raw_data[1047]) << 32 | raw_data[1046])
      .SetData524(static_cast<int64_t>(raw_data[1049]) << 32 | raw_data[1048])
      .SetData525(static_cast<int64_t>(raw_data[1051]) << 32 | raw_data[1050])
      .SetData526(static_cast<int64_t>(raw_data[1053]) << 32 | raw_data[1052])
      .SetData527(static_cast<int64_t>(raw_data[1055]) << 32 | raw_data[1054])
      .SetData528(static_cast<int64_t>(raw_data[1057]) << 32 | raw_data[1056])
      .SetData529(static_cast<int64_t>(raw_data[1059]) << 32 | raw_data[1058])
      .SetData530(static_cast<int64_t>(raw_data[1061]) << 32 | raw_data[1060])
      .SetData531(static_cast<int64_t>(raw_data[1063]) << 32 | raw_data[1062])
      .SetData532(static_cast<int64_t>(raw_data[1065]) << 32 | raw_data[1064])
      .SetData533(static_cast<int64_t>(raw_data[1067]) << 32 | raw_data[1066])
      .SetData534(static_cast<int64_t>(raw_data[1069]) << 32 | raw_data[1068])
      .SetData535(static_cast<int64_t>(raw_data[1071]) << 32 | raw_data[1070])
      .SetData536(static_cast<int64_t>(raw_data[1073]) << 32 | raw_data[1072])
      .SetData537(static_cast<int64_t>(raw_data[1075]) << 32 | raw_data[1074])
      .SetData538(static_cast<int64_t>(raw_data[1077]) << 32 | raw_data[1076])
      .SetData539(static_cast<int64_t>(raw_data[1079]) << 32 | raw_data[1078])
      .SetData540(static_cast<int64_t>(raw_data[1081]) << 32 | raw_data[1080])
      .SetData541(static_cast<int64_t>(raw_data[1083]) << 32 | raw_data[1082])
      .SetData542(static_cast<int64_t>(raw_data[1085]) << 32 | raw_data[1084])
      .SetData543(static_cast<int64_t>(raw_data[1087]) << 32 | raw_data[1086])
      .SetData544(static_cast<int64_t>(raw_data[1089]) << 32 | raw_data[1088])
      .SetData545(static_cast<int64_t>(raw_data[1091]) << 32 | raw_data[1090])
      .SetData546(static_cast<int64_t>(raw_data[1093]) << 32 | raw_data[1092])
      .SetData547(static_cast<int64_t>(raw_data[1095]) << 32 | raw_data[1094])
      .SetData548(static_cast<int64_t>(raw_data[1097]) << 32 | raw_data[1096])
      .SetData549(static_cast<int64_t>(raw_data[1099]) << 32 | raw_data[1098])
      .SetData550(static_cast<int64_t>(raw_data[1101]) << 32 | raw_data[1100])
      .SetData551(static_cast<int64_t>(raw_data[1103]) << 32 | raw_data[1102])
      .SetData552(static_cast<int64_t>(raw_data[1105]) << 32 | raw_data[1104])
      .SetData553(static_cast<int64_t>(raw_data[1107]) << 32 | raw_data[1106])
      .SetData554(static_cast<int64_t>(raw_data[1109]) << 32 | raw_data[1108])
      .SetData555(static_cast<int64_t>(raw_data[1111]) << 32 | raw_data[1110])
      .SetData556(static_cast<int64_t>(raw_data[1113]) << 32 | raw_data[1112])
      .SetData557(static_cast<int64_t>(raw_data[1115]) << 32 | raw_data[1114])
      .SetData558(static_cast<int64_t>(raw_data[1117]) << 32 | raw_data[1116])
      .SetData559(static_cast<int64_t>(raw_data[1119]) << 32 | raw_data[1118])
      .SetData560(static_cast<int64_t>(raw_data[1121]) << 32 | raw_data[1120])
      .SetData561(static_cast<int64_t>(raw_data[1123]) << 32 | raw_data[1122])
      .SetData562(static_cast<int64_t>(raw_data[1125]) << 32 | raw_data[1124])
      .SetData563(static_cast<int64_t>(raw_data[1127]) << 32 | raw_data[1126])
      .SetData564(static_cast<int64_t>(raw_data[1129]) << 32 | raw_data[1128])
      .SetData565(static_cast<int64_t>(raw_data[1131]) << 32 | raw_data[1130])
      .SetData566(static_cast<int64_t>(raw_data[1133]) << 32 | raw_data[1132])
      .SetData567(static_cast<int64_t>(raw_data[1135]) << 32 | raw_data[1134])
      .SetData568(static_cast<int64_t>(raw_data[1137]) << 32 | raw_data[1136])
      .SetData569(static_cast<int64_t>(raw_data[1139]) << 32 | raw_data[1138])
      .SetData570(static_cast<int64_t>(raw_data[1141]) << 32 | raw_data[1140])
      .SetData571(static_cast<int64_t>(raw_data[1143]) << 32 | raw_data[1142])
      .SetData572(static_cast<int64_t>(raw_data[1145]) << 32 | raw_data[1144])
      .SetData573(static_cast<int64_t>(raw_data[1147]) << 32 | raw_data[1146])
      .SetData574(static_cast<int64_t>(raw_data[1149]) << 32 | raw_data[1148])
      .SetData575(static_cast<int64_t>(raw_data[1151]) << 32 | raw_data[1150])
      .SetData576(static_cast<int64_t>(raw_data[1153]) << 32 | raw_data[1152])
      .SetData577(static_cast<int64_t>(raw_data[1155]) << 32 | raw_data[1154])
      .SetData578(static_cast<int64_t>(raw_data[1157]) << 32 | raw_data[1156])
      .SetData579(static_cast<int64_t>(raw_data[1159]) << 32 | raw_data[1158])
      .SetData580(static_cast<int64_t>(raw_data[1161]) << 32 | raw_data[1160])
      .SetData581(static_cast<int64_t>(raw_data[1163]) << 32 | raw_data[1162])
      .SetData582(static_cast<int64_t>(raw_data[1165]) << 32 | raw_data[1164])
      .SetData583(static_cast<int64_t>(raw_data[1167]) << 32 | raw_data[1166])
      .SetData584(static_cast<int64_t>(raw_data[1169]) << 32 | raw_data[1168])
      .SetData585(static_cast<int64_t>(raw_data[1171]) << 32 | raw_data[1170])
      .SetData586(static_cast<int64_t>(raw_data[1173]) << 32 | raw_data[1172])
      .SetData587(static_cast<int64_t>(raw_data[1175]) << 32 | raw_data[1174])
      .SetData588(static_cast<int64_t>(raw_data[1177]) << 32 | raw_data[1176])
      .SetData589(static_cast<int64_t>(raw_data[1179]) << 32 | raw_data[1178])
      .SetData590(static_cast<int64_t>(raw_data[1181]) << 32 | raw_data[1180])
      .SetData591(static_cast<int64_t>(raw_data[1183]) << 32 | raw_data[1182])
      .SetData592(static_cast<int64_t>(raw_data[1185]) << 32 | raw_data[1184])
      .SetData593(static_cast<int64_t>(raw_data[1187]) << 32 | raw_data[1186])
      .SetData594(static_cast<int64_t>(raw_data[1189]) << 32 | raw_data[1188])
      .SetData595(static_cast<int64_t>(raw_data[1191]) << 32 | raw_data[1190])
      .SetData596(static_cast<int64_t>(raw_data[1193]) << 32 | raw_data[1192])
      .SetData597(static_cast<int64_t>(raw_data[1195]) << 32 | raw_data[1194])
      .SetData598(static_cast<int64_t>(raw_data[1197]) << 32 | raw_data[1196])
      .SetData599(static_cast<int64_t>(raw_data[1199]) << 32 | raw_data[1198])
      .SetData600(static_cast<int64_t>(raw_data[1201]) << 32 | raw_data[1200])
      .SetData601(static_cast<int64_t>(raw_data[1203]) << 32 | raw_data[1202])
      .SetData602(static_cast<int64_t>(raw_data[1205]) << 32 | raw_data[1204])
      .SetData603(static_cast<int64_t>(raw_data[1207]) << 32 | raw_data[1206])
      .SetData604(static_cast<int64_t>(raw_data[1209]) << 32 | raw_data[1208])
      .SetData605(static_cast<int64_t>(raw_data[1211]) << 32 | raw_data[1210])
      .SetData606(static_cast<int64_t>(raw_data[1213]) << 32 | raw_data[1212])
      .SetData607(static_cast<int64_t>(raw_data[1215]) << 32 | raw_data[1214])
      .SetData608(static_cast<int64_t>(raw_data[1217]) << 32 | raw_data[1216])
      .SetData609(static_cast<int64_t>(raw_data[1219]) << 32 | raw_data[1218])
      .SetData610(static_cast<int64_t>(raw_data[1221]) << 32 | raw_data[1220])
      .SetData611(static_cast<int64_t>(raw_data[1223]) << 32 | raw_data[1222])
      .SetData612(static_cast<int64_t>(raw_data[1225]) << 32 | raw_data[1224])
      .SetData613(static_cast<int64_t>(raw_data[1227]) << 32 | raw_data[1226])
      .SetData614(static_cast<int64_t>(raw_data[1229]) << 32 | raw_data[1228])
      .SetData615(static_cast<int64_t>(raw_data[1231]) << 32 | raw_data[1230])
      .SetData616(static_cast<int64_t>(raw_data[1233]) << 32 | raw_data[1232])
      .SetData617(static_cast<int64_t>(raw_data[1235]) << 32 | raw_data[1234])
      .SetData618(static_cast<int64_t>(raw_data[1237]) << 32 | raw_data[1236])
      .SetData619(static_cast<int64_t>(raw_data[1239]) << 32 | raw_data[1238])
      .SetData620(static_cast<int64_t>(raw_data[1241]) << 32 | raw_data[1240])
      .SetData621(static_cast<int64_t>(raw_data[1243]) << 32 | raw_data[1242])
      .SetData622(static_cast<int64_t>(raw_data[1245]) << 32 | raw_data[1244])
      .SetData623(static_cast<int64_t>(raw_data[1247]) << 32 | raw_data[1246])
      .SetData624(static_cast<int64_t>(raw_data[1249]) << 32 | raw_data[1248])
      .SetData625(static_cast<int64_t>(raw_data[1251]) << 32 | raw_data[1250])
      .SetData626(static_cast<int64_t>(raw_data[1253]) << 32 | raw_data[1252])
      .SetData627(static_cast<int64_t>(raw_data[1255]) << 32 | raw_data[1254])
      .SetData628(static_cast<int64_t>(raw_data[1257]) << 32 | raw_data[1256])
      .SetData629(static_cast<int64_t>(raw_data[1259]) << 32 | raw_data[1258])
      .SetData630(static_cast<int64_t>(raw_data[1261]) << 32 | raw_data[1260])
      .SetData631(static_cast<int64_t>(raw_data[1263]) << 32 | raw_data[1262])
      .SetData632(static_cast<int64_t>(raw_data[1265]) << 32 | raw_data[1264])
      .SetData633(static_cast<int64_t>(raw_data[1267]) << 32 | raw_data[1266])
      .SetData634(static_cast<int64_t>(raw_data[1269]) << 32 | raw_data[1268])
      .SetData635(static_cast<int64_t>(raw_data[1271]) << 32 | raw_data[1270])
      .SetData636(static_cast<int64_t>(raw_data[1273]) << 32 | raw_data[1272])
      .SetData637(static_cast<int64_t>(raw_data[1275]) << 32 | raw_data[1274])
      .SetData638(static_cast<int64_t>(raw_data[1277]) << 32 | raw_data[1276])
      .SetData639(static_cast<int64_t>(raw_data[1279]) << 32 | raw_data[1278])
      .SetData640(static_cast<int64_t>(raw_data[1281]) << 32 | raw_data[1280])
      .SetData641(static_cast<int64_t>(raw_data[1283]) << 32 | raw_data[1282])
      .SetData642(static_cast<int64_t>(raw_data[1285]) << 32 | raw_data[1284])
      .SetData643(static_cast<int64_t>(raw_data[1287]) << 32 | raw_data[1286])
      .SetData644(static_cast<int64_t>(raw_data[1289]) << 32 | raw_data[1288])
      .SetData645(static_cast<int64_t>(raw_data[1291]) << 32 | raw_data[1290])
      .SetData646(static_cast<int64_t>(raw_data[1293]) << 32 | raw_data[1292])
      .SetData647(static_cast<int64_t>(raw_data[1295]) << 32 | raw_data[1294])
      .SetData648(static_cast<int64_t>(raw_data[1297]) << 32 | raw_data[1296])
      .SetData649(static_cast<int64_t>(raw_data[1299]) << 32 | raw_data[1298])
      .SetData650(static_cast<int64_t>(raw_data[1301]) << 32 | raw_data[1300])
      .SetData651(static_cast<int64_t>(raw_data[1303]) << 32 | raw_data[1302])
      .SetData652(static_cast<int64_t>(raw_data[1305]) << 32 | raw_data[1304])
      .SetData653(static_cast<int64_t>(raw_data[1307]) << 32 | raw_data[1306])
      .SetData654(static_cast<int64_t>(raw_data[1309]) << 32 | raw_data[1308])
      .SetData655(static_cast<int64_t>(raw_data[1311]) << 32 | raw_data[1310])
      .SetData656(static_cast<int64_t>(raw_data[1313]) << 32 | raw_data[1312])
      .SetData657(static_cast<int64_t>(raw_data[1315]) << 32 | raw_data[1314])
      .SetData658(static_cast<int64_t>(raw_data[1317]) << 32 | raw_data[1316])
      .SetData659(static_cast<int64_t>(raw_data[1319]) << 32 | raw_data[1318])
      .SetData660(static_cast<int64_t>(raw_data[1321]) << 32 | raw_data[1320])
      .SetData661(static_cast<int64_t>(raw_data[1323]) << 32 | raw_data[1322])
      .SetData662(static_cast<int64_t>(raw_data[1325]) << 32 | raw_data[1324])
      .SetData663(static_cast<int64_t>(raw_data[1327]) << 32 | raw_data[1326])
      .SetData664(static_cast<int64_t>(raw_data[1329]) << 32 | raw_data[1328])
      .SetData665(static_cast<int64_t>(raw_data[1331]) << 32 | raw_data[1330])
      .SetData666(static_cast<int64_t>(raw_data[1333]) << 32 | raw_data[1332])
      .SetData667(static_cast<int64_t>(raw_data[1335]) << 32 | raw_data[1334])
      .SetData668(static_cast<int64_t>(raw_data[1337]) << 32 | raw_data[1336])
      .SetData669(static_cast<int64_t>(raw_data[1339]) << 32 | raw_data[1338])
      .SetData670(static_cast<int64_t>(raw_data[1341]) << 32 | raw_data[1340])
      .SetData671(static_cast<int64_t>(raw_data[1343]) << 32 | raw_data[1342])
      .SetData672(static_cast<int64_t>(raw_data[1345]) << 32 | raw_data[1344])
      .SetData673(static_cast<int64_t>(raw_data[1347]) << 32 | raw_data[1346])
      .SetData674(static_cast<int64_t>(raw_data[1349]) << 32 | raw_data[1348])
      .SetData675(static_cast<int64_t>(raw_data[1351]) << 32 | raw_data[1350])
      .SetData676(static_cast<int64_t>(raw_data[1353]) << 32 | raw_data[1352])
      .SetData677(static_cast<int64_t>(raw_data[1355]) << 32 | raw_data[1354])
      .SetData678(static_cast<int64_t>(raw_data[1357]) << 32 | raw_data[1356])
      .SetData679(static_cast<int64_t>(raw_data[1359]) << 32 | raw_data[1358])
      .SetData680(static_cast<int64_t>(raw_data[1361]) << 32 | raw_data[1360])
      .SetData681(static_cast<int64_t>(raw_data[1363]) << 32 | raw_data[1362])
      .SetData682(static_cast<int64_t>(raw_data[1365]) << 32 | raw_data[1364])
      .SetData683(static_cast<int64_t>(raw_data[1367]) << 32 | raw_data[1366])
      .SetData684(static_cast<int64_t>(raw_data[1369]) << 32 | raw_data[1368])
      .SetData685(static_cast<int64_t>(raw_data[1371]) << 32 | raw_data[1370])
      .SetData686(static_cast<int64_t>(raw_data[1373]) << 32 | raw_data[1372])
      .SetData687(static_cast<int64_t>(raw_data[1375]) << 32 | raw_data[1374])
      .SetData688(static_cast<int64_t>(raw_data[1377]) << 32 | raw_data[1376])
      .SetData689(static_cast<int64_t>(raw_data[1379]) << 32 | raw_data[1378])
      .SetData690(static_cast<int64_t>(raw_data[1381]) << 32 | raw_data[1380])
      .SetData691(static_cast<int64_t>(raw_data[1383]) << 32 | raw_data[1382])
      .SetData692(static_cast<int64_t>(raw_data[1385]) << 32 | raw_data[1384])
      .SetData693(static_cast<int64_t>(raw_data[1387]) << 32 | raw_data[1386])
      .SetData694(static_cast<int64_t>(raw_data[1389]) << 32 | raw_data[1388])
      .SetData695(static_cast<int64_t>(raw_data[1391]) << 32 | raw_data[1390])
      .SetData696(static_cast<int64_t>(raw_data[1393]) << 32 | raw_data[1392])
      .SetData697(static_cast<int64_t>(raw_data[1395]) << 32 | raw_data[1394])
      .SetData698(static_cast<int64_t>(raw_data[1397]) << 32 | raw_data[1396])
      .SetData699(static_cast<int64_t>(raw_data[1399]) << 32 | raw_data[1398])
      .SetData700(static_cast<int64_t>(raw_data[1401]) << 32 | raw_data[1400])
      .SetData701(static_cast<int64_t>(raw_data[1403]) << 32 | raw_data[1402])
      .SetData702(static_cast<int64_t>(raw_data[1405]) << 32 | raw_data[1404])
      .SetData703(static_cast<int64_t>(raw_data[1407]) << 32 | raw_data[1406])
      .SetData704(static_cast<int64_t>(raw_data[1409]) << 32 | raw_data[1408])
      .SetData705(static_cast<int64_t>(raw_data[1411]) << 32 | raw_data[1410])
      .SetData706(static_cast<int64_t>(raw_data[1413]) << 32 | raw_data[1412])
      .SetData707(static_cast<int64_t>(raw_data[1415]) << 32 | raw_data[1414])
      .SetData708(static_cast<int64_t>(raw_data[1417]) << 32 | raw_data[1416])
      .SetData709(static_cast<int64_t>(raw_data[1419]) << 32 | raw_data[1418])
      .SetData710(static_cast<int64_t>(raw_data[1421]) << 32 | raw_data[1420])
      .SetData711(static_cast<int64_t>(raw_data[1423]) << 32 | raw_data[1422])
      .SetData712(static_cast<int64_t>(raw_data[1425]) << 32 | raw_data[1424])
      .SetData713(static_cast<int64_t>(raw_data[1427]) << 32 | raw_data[1426])
      .SetData714(static_cast<int64_t>(raw_data[1429]) << 32 | raw_data[1428])
      .SetData715(static_cast<int64_t>(raw_data[1431]) << 32 | raw_data[1430])
      .SetData716(static_cast<int64_t>(raw_data[1433]) << 32 | raw_data[1432])
      .SetData717(static_cast<int64_t>(raw_data[1435]) << 32 | raw_data[1434])
      .SetData718(static_cast<int64_t>(raw_data[1437]) << 32 | raw_data[1436])
      .SetData719(static_cast<int64_t>(raw_data[1439]) << 32 | raw_data[1438])
      .SetData720(static_cast<int64_t>(raw_data[1441]) << 32 | raw_data[1440])
      .SetData721(static_cast<int64_t>(raw_data[1443]) << 32 | raw_data[1442])
      .SetData722(static_cast<int64_t>(raw_data[1445]) << 32 | raw_data[1444])
      .SetData723(static_cast<int64_t>(raw_data[1447]) << 32 | raw_data[1446])
      .SetData724(static_cast<int64_t>(raw_data[1449]) << 32 | raw_data[1448])
      .SetData725(static_cast<int64_t>(raw_data[1451]) << 32 | raw_data[1450])
      .SetData726(static_cast<int64_t>(raw_data[1453]) << 32 | raw_data[1452])
      .SetData727(static_cast<int64_t>(raw_data[1455]) << 32 | raw_data[1454])
      .SetData728(static_cast<int64_t>(raw_data[1457]) << 32 | raw_data[1456])
      .SetData729(static_cast<int64_t>(raw_data[1459]) << 32 | raw_data[1458])
      .SetData730(static_cast<int64_t>(raw_data[1461]) << 32 | raw_data[1460])
      .SetData731(static_cast<int64_t>(raw_data[1463]) << 32 | raw_data[1462])
      .SetData732(static_cast<int64_t>(raw_data[1465]) << 32 | raw_data[1464])
      .SetData733(static_cast<int64_t>(raw_data[1467]) << 32 | raw_data[1466])
      .SetData734(static_cast<int64_t>(raw_data[1469]) << 32 | raw_data[1468])
      .SetData735(static_cast<int64_t>(raw_data[1471]) << 32 | raw_data[1470])
      .SetData736(static_cast<int64_t>(raw_data[1473]) << 32 | raw_data[1472])
      .SetData737(static_cast<int64_t>(raw_data[1475]) << 32 | raw_data[1474])
      .SetData738(static_cast<int64_t>(raw_data[1477]) << 32 | raw_data[1476])
      .SetData739(static_cast<int64_t>(raw_data[1479]) << 32 | raw_data[1478])
      .SetData740(static_cast<int64_t>(raw_data[1481]) << 32 | raw_data[1480])
      .SetData741(static_cast<int64_t>(raw_data[1483]) << 32 | raw_data[1482])
      .SetData742(static_cast<int64_t>(raw_data[1485]) << 32 | raw_data[1484])
      .SetData743(static_cast<int64_t>(raw_data[1487]) << 32 | raw_data[1486])
      .SetData744(static_cast<int64_t>(raw_data[1489]) << 32 | raw_data[1488])
      .SetData745(static_cast<int64_t>(raw_data[1491]) << 32 | raw_data[1490])
      .SetData746(static_cast<int64_t>(raw_data[1493]) << 32 | raw_data[1492])
      .SetData747(static_cast<int64_t>(raw_data[1495]) << 32 | raw_data[1494])
      .SetData748(static_cast<int64_t>(raw_data[1497]) << 32 |
```