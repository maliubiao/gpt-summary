Response:
Let's break down the thought process for answering the request about the `encoding_tables_test.cc` file.

**1. Understanding the Core Request:**

The primary goal is to understand the *functionality* of the given C++ code snippet, within the context of the Chromium Blink engine. Specifically, we need to identify its role in text encoding and its relation to web technologies (JavaScript, HTML, CSS).

**2. Initial Code Analysis (The Provided Snippet):**

The provided code is a large array of integer pairs. Each pair likely represents a mapping between two values. Given the file name "encoding_tables_test.cc", and the `wtf/text` directory, the immediate assumption is that these pairs are related to character encoding. Specifically, the first integer might be a character code point (or an index representing one), and the second integer is likely its representation in a specific encoding.

**3. Connecting to Encoding Concepts:**

Knowing it's about encoding, the next step is to think about *why* such a table would exist. Web browsers need to handle various character encodings (UTF-8, ISO-8859-1, etc.) to display text correctly. These tables are essential for converting between different encoding schemes.

**4. Relating to Web Technologies (JavaScript, HTML, CSS):**

* **JavaScript:**  JavaScript works with strings, which are sequences of Unicode characters. When JavaScript interacts with the browser or the network, encoding becomes relevant. For instance, when sending data to a server or receiving data, JavaScript needs to understand the encoding.
* **HTML:**  HTML documents specify their encoding using the `<meta charset>` tag. The browser relies on encoding tables to interpret the bytes of the HTML file and render the text correctly.
* **CSS:** While CSS primarily deals with styling, it can also involve text content (e.g., using `content` property). The encoding of the CSS file itself matters, though the provided snippet is more likely about handling content *within* the rendered HTML.

**5. Forming Hypotheses and Examples:**

Based on the initial analysis, we can formulate some hypotheses about the file's functionality and its relation to web technologies:

* **Hypothesis 1: Mapping Specific Characters:** The table might be mapping characters that are problematic or have special handling in certain encodings.
* **Hypothesis 2: Testing Encoding Conversions:**  The `_test.cc` suffix suggests this is a test file. It's highly likely the file contains test cases that verify the correctness of encoding conversion logic.

To illustrate the connection to web technologies, let's create some examples:

* **JavaScript Example:**  Imagine a user types a special character in a form field. JavaScript needs to ensure this character is encoded correctly when the form is submitted.
* **HTML Example:** If an HTML file is encoded in GBK (a Chinese encoding), the browser uses tables like this to map the GBK bytes to the correct Unicode characters for display.
* **CSS Example:** Although less direct, consider a CSS file with `@charset "UTF-8";`. The browser uses encoding knowledge to interpret the CSS rules correctly.

**6. Considering Potential User/Programming Errors:**

Encoding issues are a common source of errors. Some examples:

* **Incorrect `charset` declaration:**  If the HTML `charset` doesn't match the actual encoding of the file, characters will be displayed incorrectly (mojibake).
* **Assuming a default encoding:**  Programmers might forget to handle encoding explicitly, leading to problems when dealing with non-ASCII characters.
* **Mixing encodings:**  If different parts of a web application use inconsistent encodings, data corruption or display issues can occur.

**7. Addressing the "Logic Inference" and "Input/Output" Requirement:**

Since it's a *test* file, the logic is primarily about *verifying* existing encoding logic. The "input" would be a character or a sequence of bytes in a specific encoding, and the "output" would be the expected representation in another encoding (or the confirmation that the conversion is handled correctly).

Given the provided snippet *only* contains the data table, it's hard to provide a specific *logical inference* within this snippet alone. The inference is at a higher level: this table *supports* encoding logic elsewhere in the engine.

However, we can make a simple assumption for illustration:

* **Assumption:** The table maps Unicode code points to their representation in some other encoding (e.g., a legacy encoding).
* **Input:**  The Unicode code point `9359`.
* **Output:** The corresponding encoded value `0xCF9F`.

**8. Synthesizing the Summary:**

Finally, we need to summarize the functionality based on the analysis. The key points are:

* It's a test file for encoding tables.
* The data represents mappings between character representations.
* It supports the correct rendering of text in different encodings.

**Self-Correction/Refinement:**

Initially, I might have focused too narrowly on the specific data in the snippet. It's important to remember the context: it's a *test* file. Therefore, its primary function isn't just to *store* encoding data, but to *verify* the correctness of encoding *handling*. This leads to emphasizing the testing aspect in the final answer. Also, while CSS encoding is relevant, the provided snippet is more directly related to HTML content and data handling (like in forms). Refining the examples to reflect this directness improves the answer.
根据您提供的代码片段，`encoding_tables_test.cc` 文件（这是第13部分，共24部分）的主要功能是 **测试硬编码的字符编码转换表**。

**更详细的功能分解：**

1. **存储测试数据:**  该文件包含了大量的静态数据，这些数据以 `{code_point, encoded_value}` 的形式存在。`code_point` 通常是一个Unicode字符的数字表示，而 `encoded_value` 是该字符在特定编码方案下的字节表示（通常是十六进制）。

2. **验证编码转换的正确性:**  `_test.cc` 后缀表明这是一个测试文件。这个文件很可能是用来测试 Blink 引擎中字符编码转换功能的正确性。它会拿这些硬编码的数据作为“真值”，与引擎实际执行编码转换的结果进行比对，以确保转换的准确性。

3. **覆盖特定的字符映射:**  从数据中可以看出，这些映射覆盖了从某个起始点到结束点的连续字符，同时也包含了一些跳跃的字符。这表明测试的目的是为了验证特定编码方案下，某些特定字符的转换是否正确。

**与 JavaScript, HTML, CSS 的关系：**

`encoding_tables_test.cc` 文件本身是用 C++ 编写的，直接与 JavaScript, HTML, CSS 的代码执行没有直接关系。但是，它所测试的字符编码转换功能对于这三者都至关重要：

* **HTML:**
    * **举例说明：** 当浏览器解析 HTML 文件时，它需要知道文件的字符编码（通常在 `<meta charset="...">` 声明）。然后，它会使用类似这里测试的编码表，将 HTML 文件中特定编码的字节流转换为 Unicode 字符，以便正确渲染页面上的文本。如果编码转换错误，就会出现乱码。例如，一个 HTML 文件声明为 UTF-8，但实际包含 GBK 编码的字符，就可能导致显示问题。这个测试文件确保了 Blink 引擎能正确处理各种编码的 HTML 文件。

* **JavaScript:**
    * **举例说明：** JavaScript 字符串内部使用 Unicode 表示。当 JavaScript 需要与外部交互（例如，通过 `fetch` API 从服务器获取数据，或通过表单提交数据）时，就需要进行字符编码和解码。例如，当 JavaScript 将包含特殊字符的数据发送到服务器时，浏览器需要根据服务器预期的编码进行编码。反之，接收到服务器响应时，也需要根据响应头的编码进行解码。这个测试文件保证了 JavaScript 在进行此类操作时，字符编码转换的准确性。

* **CSS:**
    * **举例说明：** CSS 文件本身也需要指定字符编码（通过 `@charset` 规则）。浏览器需要正确解析 CSS 文件中的字符，包括选择器、属性值等。虽然 CSS 主要关注样式，但其中也可能包含文本内容，例如 `content` 属性。确保 CSS 文件的编码被正确理解是浏览器渲染页面的重要一步。这个测试文件间接地保证了 CSS 文件的字符能被正确处理。

**逻辑推理 (假设输入与输出):**

假设测试用例会遍历这个数据表。

* **假设输入:**  测试代码会从数据表中取出一对值，例如 `{9359, 0xCF9F}`。
* **逻辑推理:**  测试代码会告知编码转换函数，将 Unicode 代码点 `9359` 转换为目标编码。
* **预期输出:**  编码转换函数返回的字节表示应该与数据表中的 `0xCF9F` 相匹配。如果匹配，则测试通过，否则测试失败。

**用户或编程常见的使用错误 (举例说明):**

这些测试旨在防止引擎内部的编码转换错误，但用户或开发者也可能犯一些与编码相关的错误：

* **HTML 页面编码声明错误：** 用户可能创建了一个 UTF-8 编码的 HTML 文件，但错误地将 `<meta charset="ISO-8859-1">` 放在了 HTML 文档中。这将导致浏览器使用错误的编码解释文件内容，从而显示乱码。
* **JavaScript 处理编码不一致的数据：** 开发者可能从服务器接收到 GBK 编码的数据，但在 JavaScript 中没有进行正确的解码，就直接将其作为 UTF-8 字符串处理，导致数据损坏或显示错误。
* **CSS 文件编码与声明不符：** 开发者可能创建了一个使用了特定字符的 CSS 文件，并声明了 `@charset "UTF-8";`，但实际保存文件时使用了其他编码（例如，ANSI）。这会导致浏览器无法正确解析 CSS 文件。

**功能归纳 (作为第13部分，共24部分):**

作为 `encoding_tables_test.cc` 文件的一部分（可能是众多测试不同编码方案或不同方面的测试文件之一），这第13部分的功能是 **提供一组特定的字符到字节表示的硬编码映射数据，用于测试 Blink 引擎在处理特定字符编码转换时的正确性。**  它可以被看作是编码转换功能的基础性单元测试，确保引擎能够正确处理特定字符的映射关系。其他部分可能测试更复杂的场景，例如不同编码之间的转换、错误处理等。

### 提示词
```
这是目录为blink/renderer/platform/wtf/text/encoding_tables_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第13部分，共24部分，请归纳一下它的功能
```

### 源代码
```cpp
F9E},  {9359, 0xCF9F},
    {9360, 0xCFA0},  {9361, 0xCFA2},  {9362, 0xCFA3},  {9363, 0xCFA4},
    {9364, 0xCFA5},  {9365, 0xCFA6},  {9366, 0xCFA7},  {9367, 0xCFA9},
    {9374, 0xCFAA},  {9375, 0xCFAB},  {9376, 0xCFAC},  {9377, 0xCFAD},
    {9378, 0xCFAE},  {9379, 0xCFAF},  {9380, 0xCFB1},  {9381, 0xCFB2},
    {9382, 0xCFB3},  {9383, 0xCFB4},  {9384, 0xCFB5},  {9385, 0xCFB6},
    {9386, 0xCFB7},  {9387, 0xCFB8},  {9388, 0xCFB9},  {9389, 0xCFBA},
    {9390, 0xCFBB},  {9391, 0xCFBC},  {9392, 0xCFBD},  {9393, 0xCFBE},
    {9394, 0xCFBF},  {9395, 0xCFC0},  {9396, 0xCFC1},  {9397, 0xCFC2},
    {9398, 0xCFC3},  {9399, 0xCFC5},  {9400, 0xCFC6},  {9401, 0xCFC7},
    {9402, 0xCFC8},  {9403, 0xCFC9},  {9404, 0xCFCA},  {9405, 0xCFCB},
    {9406, 0xAE79},  {9407, 0xAE7B},  {9408, 0xAE7C},  {9409, 0xAE7D},
    {9410, 0xAE84},  {9411, 0xAE85},  {9412, 0xAE8C},  {9413, 0xAEBC},
    {9414, 0xAEBD},  {9415, 0xAEBE},  {9416, 0xAEC0},  {9417, 0xAEC4},
    {9418, 0xAECC},  {9419, 0xAECD},  {9420, 0xAECF},  {9421, 0xAED0},
    {9422, 0xAED1},  {9423, 0xAED8},  {9424, 0xAED9},  {9425, 0xAEDC},
    {9426, 0xAEE8},  {9427, 0xAEEB},  {9428, 0xAEED},  {9429, 0xAEF4},
    {9430, 0xAEF8},  {9431, 0xAEFC},  {9432, 0xAF07},  {9433, 0xAF08},
    {9434, 0xAF0D},  {9435, 0xAF10},  {9436, 0xAF2C},  {9437, 0xAF2D},
    {9438, 0xAF30},  {9439, 0xAF32},  {9440, 0xAF34},  {9441, 0xAF3C},
    {9442, 0xAF3D},  {9443, 0xAF3F},  {9444, 0xAF41},  {9445, 0xAF42},
    {9446, 0xAF43},  {9447, 0xAF48},  {9448, 0xAF49},  {9449, 0xAF50},
    {9450, 0xAF5C},  {9451, 0xAF5D},  {9452, 0xAF64},  {9453, 0xAF65},
    {9454, 0xAF79},  {9455, 0xAF80},  {9456, 0xAF84},  {9457, 0xAF88},
    {9458, 0xAF90},  {9459, 0xAF91},  {9460, 0xAF95},  {9461, 0xAF9C},
    {9462, 0xAFB8},  {9463, 0xAFB9},  {9464, 0xAFBC},  {9465, 0xAFC0},
    {9466, 0xAFC7},  {9467, 0xAFC8},  {9468, 0xAFC9},  {9469, 0xAFCB},
    {9470, 0xAFCD},  {9471, 0xAFCE},  {9472, 0xAFD4},  {9473, 0xAFDC},
    {9474, 0xAFE8},  {9475, 0xAFE9},  {9476, 0xAFF0},  {9477, 0xAFF1},
    {9478, 0xAFF4},  {9479, 0xAFF8},  {9480, 0xB000},  {9481, 0xB001},
    {9482, 0xB004},  {9483, 0xB00C},  {9484, 0xB010},  {9485, 0xB014},
    {9486, 0xB01C},  {9487, 0xB01D},  {9488, 0xB028},  {9489, 0xB044},
    {9490, 0xB045},  {9491, 0xB048},  {9492, 0xB04A},  {9493, 0xB04C},
    {9494, 0xB04E},  {9495, 0xB053},  {9496, 0xB054},  {9497, 0xB055},
    {9498, 0xB057},  {9499, 0xB059},  {9500, 0xCFCC},  {9501, 0xCFCD},
    {9502, 0xCFCE},  {9503, 0xCFCF},  {9504, 0xCFD0},  {9505, 0xCFD1},
    {9506, 0xCFD2},  {9507, 0xCFD3},  {9508, 0xCFD4},  {9509, 0xCFD5},
    {9510, 0xCFD6},  {9511, 0xCFD7},  {9512, 0xCFD8},  {9513, 0xCFD9},
    {9514, 0xCFDA},  {9515, 0xCFDB},  {9516, 0xCFDC},  {9517, 0xCFDD},
    {9518, 0xCFDE},  {9519, 0xCFDF},  {9520, 0xCFE2},  {9521, 0xCFE3},
    {9522, 0xCFE5},  {9523, 0xCFE6},  {9524, 0xCFE7},  {9525, 0xCFE9},
    {9532, 0xCFEA},  {9533, 0xCFEB},  {9534, 0xCFEC},  {9535, 0xCFED},
    {9536, 0xCFEE},  {9537, 0xCFEF},  {9538, 0xCFF2},  {9539, 0xCFF4},
    {9540, 0xCFF6},  {9541, 0xCFF7},  {9542, 0xCFF8},  {9543, 0xCFF9},
    {9544, 0xCFFA},  {9545, 0xCFFB},  {9546, 0xCFFD},  {9547, 0xCFFE},
    {9548, 0xCFFF},  {9549, 0xD001},  {9550, 0xD002},  {9551, 0xD003},
    {9552, 0xD005},  {9553, 0xD006},  {9554, 0xD007},  {9555, 0xD008},
    {9556, 0xD009},  {9557, 0xD00A},  {9564, 0xD00B},  {9565, 0xD00C},
    {9566, 0xD00D},  {9567, 0xD00E},  {9568, 0xD00F},  {9569, 0xD010},
    {9570, 0xD012},  {9571, 0xD013},  {9572, 0xD014},  {9573, 0xD015},
    {9574, 0xD016},  {9575, 0xD017},  {9576, 0xD019},  {9577, 0xD01A},
    {9578, 0xD01B},  {9579, 0xD01C},  {9580, 0xD01D},  {9581, 0xD01E},
    {9582, 0xD01F},  {9583, 0xD020},  {9584, 0xD021},  {9585, 0xD022},
    {9586, 0xD023},  {9587, 0xD024},  {9588, 0xD025},  {9589, 0xD026},
    {9590, 0xD027},  {9591, 0xD028},  {9592, 0xD029},  {9593, 0xD02A},
    {9594, 0xD02B},  {9595, 0xD02C},  {9596, 0xB05D},  {9597, 0xB07C},
    {9598, 0xB07D},  {9599, 0xB080},  {9600, 0xB084},  {9601, 0xB08C},
    {9602, 0xB08D},  {9603, 0xB08F},  {9604, 0xB091},  {9605, 0xB098},
    {9606, 0xB099},  {9607, 0xB09A},  {9608, 0xB09C},  {9609, 0xB09F},
    {9610, 0xB0A0},  {9611, 0xB0A1},  {9612, 0xB0A2},  {9613, 0xB0A8},
    {9614, 0xB0A9},  {9615, 0xB0AB},  {9616, 0xB0AC},  {9617, 0xB0AD},
    {9618, 0xB0AE},  {9619, 0xB0AF},  {9620, 0xB0B1},  {9621, 0xB0B3},
    {9622, 0xB0B4},  {9623, 0xB0B5},  {9624, 0xB0B8},  {9625, 0xB0BC},
    {9626, 0xB0C4},  {9627, 0xB0C5},  {9628, 0xB0C7},  {9629, 0xB0C8},
    {9630, 0xB0C9},  {9631, 0xB0D0},  {9632, 0xB0D1},  {9633, 0xB0D4},
    {9634, 0xB0D8},  {9635, 0xB0E0},  {9636, 0xB0E5},  {9637, 0xB108},
    {9638, 0xB109},  {9639, 0xB10B},  {9640, 0xB10C},  {9641, 0xB110},
    {9642, 0xB112},  {9643, 0xB113},  {9644, 0xB118},  {9645, 0xB119},
    {9646, 0xB11B},  {9647, 0xB11C},  {9648, 0xB11D},  {9649, 0xB123},
    {9650, 0xB124},  {9651, 0xB125},  {9652, 0xB128},  {9653, 0xB12C},
    {9654, 0xB134},  {9655, 0xB135},  {9656, 0xB137},  {9657, 0xB138},
    {9658, 0xB139},  {9659, 0xB140},  {9660, 0xB141},  {9661, 0xB144},
    {9662, 0xB148},  {9663, 0xB150},  {9664, 0xB151},  {9665, 0xB154},
    {9666, 0xB155},  {9667, 0xB158},  {9668, 0xB15C},  {9669, 0xB160},
    {9670, 0xB178},  {9671, 0xB179},  {9672, 0xB17C},  {9673, 0xB180},
    {9674, 0xB182},  {9675, 0xB188},  {9676, 0xB189},  {9677, 0xB18B},
    {9678, 0xB18D},  {9679, 0xB192},  {9680, 0xB193},  {9681, 0xB194},
    {9682, 0xB198},  {9683, 0xB19C},  {9684, 0xB1A8},  {9685, 0xB1CC},
    {9686, 0xB1D0},  {9687, 0xB1D4},  {9688, 0xB1DC},  {9689, 0xB1DD},
    {9690, 0xD02E},  {9691, 0xD02F},  {9692, 0xD030},  {9693, 0xD031},
    {9694, 0xD032},  {9695, 0xD033},  {9696, 0xD036},  {9697, 0xD037},
    {9698, 0xD039},  {9699, 0xD03A},  {9700, 0xD03B},  {9701, 0xD03D},
    {9702, 0xD03E},  {9703, 0xD03F},  {9704, 0xD040},  {9705, 0xD041},
    {9706, 0xD042},  {9707, 0xD043},  {9708, 0xD046},  {9709, 0xD048},
    {9710, 0xD04A},  {9711, 0xD04B},  {9712, 0xD04C},  {9713, 0xD04D},
    {9714, 0xD04E},  {9715, 0xD04F},  {9722, 0xD051},  {9723, 0xD052},
    {9724, 0xD053},  {9725, 0xD055},  {9726, 0xD056},  {9727, 0xD057},
    {9728, 0xD059},  {9729, 0xD05A},  {9730, 0xD05B},  {9731, 0xD05C},
    {9732, 0xD05D},  {9733, 0xD05E},  {9734, 0xD05F},  {9735, 0xD061},
    {9736, 0xD062},  {9737, 0xD063},  {9738, 0xD064},  {9739, 0xD065},
    {9740, 0xD066},  {9741, 0xD067},  {9742, 0xD068},  {9743, 0xD069},
    {9744, 0xD06A},  {9745, 0xD06B},  {9746, 0xD06E},  {9747, 0xD06F},
    {9754, 0xD071},  {9755, 0xD072},  {9756, 0xD073},  {9757, 0xD075},
    {9758, 0xD076},  {9759, 0xD077},  {9760, 0xD078},  {9761, 0xD079},
    {9762, 0xD07A},  {9763, 0xD07B},  {9764, 0xD07E},  {9765, 0xD07F},
    {9766, 0xD080},  {9767, 0xD082},  {9768, 0xD083},  {9769, 0xD084},
    {9770, 0xD085},  {9771, 0xD086},  {9772, 0xD087},  {9773, 0xD088},
    {9774, 0xD089},  {9775, 0xD08A},  {9776, 0xD08B},  {9777, 0xD08C},
    {9778, 0xD08D},  {9779, 0xD08E},  {9780, 0xD08F},  {9781, 0xD090},
    {9782, 0xD091},  {9783, 0xD092},  {9784, 0xD093},  {9785, 0xD094},
    {9786, 0xB1DF},  {9787, 0xB1E8},  {9788, 0xB1E9},  {9789, 0xB1EC},
    {9790, 0xB1F0},  {9791, 0xB1F9},  {9792, 0xB1FB},  {9793, 0xB1FD},
    {9794, 0xB204},  {9795, 0xB205},  {9796, 0xB208},  {9797, 0xB20B},
    {9798, 0xB20C},  {9799, 0xB214},  {9800, 0xB215},  {9801, 0xB217},
    {9802, 0xB219},  {9803, 0xB220},  {9804, 0xB234},  {9805, 0xB23C},
    {9806, 0xB258},  {9807, 0xB25C},  {9808, 0xB260},  {9809, 0xB268},
    {9810, 0xB269},  {9811, 0xB274},  {9812, 0xB275},  {9813, 0xB27C},
    {9814, 0xB284},  {9815, 0xB285},  {9816, 0xB289},  {9817, 0xB290},
    {9818, 0xB291},  {9819, 0xB294},  {9820, 0xB298},  {9821, 0xB299},
    {9822, 0xB29A},  {9823, 0xB2A0},  {9824, 0xB2A1},  {9825, 0xB2A3},
    {9826, 0xB2A5},  {9827, 0xB2A6},  {9828, 0xB2AA},  {9829, 0xB2AC},
    {9830, 0xB2B0},  {9831, 0xB2B4},  {9832, 0xB2C8},  {9833, 0xB2C9},
    {9834, 0xB2CC},  {9835, 0xB2D0},  {9836, 0xB2D2},  {9837, 0xB2D8},
    {9838, 0xB2D9},  {9839, 0xB2DB},  {9840, 0xB2DD},  {9841, 0xB2E2},
    {9842, 0xB2E4},  {9843, 0xB2E5},  {9844, 0xB2E6},  {9845, 0xB2E8},
    {9846, 0xB2EB},  {9847, 0xB2EC},  {9848, 0xB2ED},  {9849, 0xB2EE},
    {9850, 0xB2EF},  {9851, 0xB2F3},  {9852, 0xB2F4},  {9853, 0xB2F5},
    {9854, 0xB2F7},  {9855, 0xB2F8},  {9856, 0xB2F9},  {9857, 0xB2FA},
    {9858, 0xB2FB},  {9859, 0xB2FF},  {9860, 0xB300},  {9861, 0xB301},
    {9862, 0xB304},  {9863, 0xB308},  {9864, 0xB310},  {9865, 0xB311},
    {9866, 0xB313},  {9867, 0xB314},  {9868, 0xB315},  {9869, 0xB31C},
    {9870, 0xB354},  {9871, 0xB355},  {9872, 0xB356},  {9873, 0xB358},
    {9874, 0xB35B},  {9875, 0xB35C},  {9876, 0xB35E},  {9877, 0xB35F},
    {9878, 0xB364},  {9879, 0xB365},  {9880, 0xD095},  {9881, 0xD096},
    {9882, 0xD097},  {9883, 0xD098},  {9884, 0xD099},  {9885, 0xD09A},
    {9886, 0xD09B},  {9887, 0xD09C},  {9888, 0xD09D},  {9889, 0xD09E},
    {9890, 0xD09F},  {9891, 0xD0A0},  {9892, 0xD0A1},  {9893, 0xD0A2},
    {9894, 0xD0A3},  {9895, 0xD0A6},  {9896, 0xD0A7},  {9897, 0xD0A9},
    {9898, 0xD0AA},  {9899, 0xD0AB},  {9900, 0xD0AD},  {9901, 0xD0AE},
    {9902, 0xD0AF},  {9903, 0xD0B0},  {9904, 0xD0B1},  {9905, 0xD0B2},
    {9912, 0xD0B3},  {9913, 0xD0B6},  {9914, 0xD0B8},  {9915, 0xD0BA},
    {9916, 0xD0BB},  {9917, 0xD0BC},  {9918, 0xD0BD},  {9919, 0xD0BE},
    {9920, 0xD0BF},  {9921, 0xD0C2},  {9922, 0xD0C3},  {9923, 0xD0C5},
    {9924, 0xD0C6},  {9925, 0xD0C7},  {9926, 0xD0CA},  {9927, 0xD0CB},
    {9928, 0xD0CC},  {9929, 0xD0CD},  {9930, 0xD0CE},  {9931, 0xD0CF},
    {9932, 0xD0D2},  {9933, 0xD0D6},  {9934, 0xD0D7},  {9935, 0xD0D8},
    {9936, 0xD0D9},  {9937, 0xD0DA},  {9944, 0xD0DB},  {9945, 0xD0DE},
    {9946, 0xD0DF},  {9947, 0xD0E1},  {9948, 0xD0E2},  {9949, 0xD0E3},
    {9950, 0xD0E5},  {9951, 0xD0E6},  {9952, 0xD0E7},  {9953, 0xD0E8},
    {9954, 0xD0E9},  {9955, 0xD0EA},  {9956, 0xD0EB},  {9957, 0xD0EE},
    {9958, 0xD0F2},  {9959, 0xD0F3},  {9960, 0xD0F4},  {9961, 0xD0F5},
    {9962, 0xD0F6},  {9963, 0xD0F7},  {9964, 0xD0F9},  {9965, 0xD0FA},
    {9966, 0xD0FB},  {9967, 0xD0FC},  {9968, 0xD0FD},  {9969, 0xD0FE},
    {9970, 0xD0FF},  {9971, 0xD100},  {9972, 0xD101},  {9973, 0xD102},
    {9974, 0xD103},  {9975, 0xD104},  {9976, 0xB367},  {9977, 0xB369},
    {9978, 0xB36B},  {9979, 0xB36E},  {9980, 0xB370},  {9981, 0xB371},
    {9982, 0xB374},  {9983, 0xB378},  {9984, 0xB380},  {9985, 0xB381},
    {9986, 0xB383},  {9987, 0xB384},  {9988, 0xB385},  {9989, 0xB38C},
    {9990, 0xB390},  {9991, 0xB394},  {9992, 0xB3A0},  {9993, 0xB3A1},
    {9994, 0xB3A8},  {9995, 0xB3AC},  {9996, 0xB3C4},  {9997, 0xB3C5},
    {9998, 0xB3C8},  {9999, 0xB3CB},  {10000, 0xB3CC}, {10001, 0xB3CE},
    {10002, 0xB3D0}, {10003, 0xB3D4}, {10004, 0xB3D5}, {10005, 0xB3D7},
    {10006, 0xB3D9}, {10007, 0xB3DB}, {10008, 0xB3DD}, {10009, 0xB3E0},
    {10010, 0xB3E4}, {10011, 0xB3E8}, {10012, 0xB3FC}, {10013, 0xB410},
    {10014, 0xB418}, {10015, 0xB41C}, {10016, 0xB420}, {10017, 0xB428},
    {10018, 0xB429}, {10019, 0xB42B}, {10020, 0xB434}, {10021, 0xB450},
    {10022, 0xB451}, {10023, 0xB454}, {10024, 0xB458}, {10025, 0xB460},
    {10026, 0xB461}, {10027, 0xB463}, {10028, 0xB465}, {10029, 0xB46C},
    {10030, 0xB480}, {10031, 0xB488}, {10032, 0xB49D}, {10033, 0xB4A4},
    {10034, 0xB4A8}, {10035, 0xB4AC}, {10036, 0xB4B5}, {10037, 0xB4B7},
    {10038, 0xB4B9}, {10039, 0xB4C0}, {10040, 0xB4C4}, {10041, 0xB4C8},
    {10042, 0xB4D0}, {10043, 0xB4D5}, {10044, 0xB4DC}, {10045, 0xB4DD},
    {10046, 0xB4E0}, {10047, 0xB4E3}, {10048, 0xB4E4}, {10049, 0xB4E6},
    {10050, 0xB4EC}, {10051, 0xB4ED}, {10052, 0xB4EF}, {10053, 0xB4F1},
    {10054, 0xB4F8}, {10055, 0xB514}, {10056, 0xB515}, {10057, 0xB518},
    {10058, 0xB51B}, {10059, 0xB51C}, {10060, 0xB524}, {10061, 0xB525},
    {10062, 0xB527}, {10063, 0xB528}, {10064, 0xB529}, {10065, 0xB52A},
    {10066, 0xB530}, {10067, 0xB531}, {10068, 0xB534}, {10069, 0xB538},
    {10070, 0xD105}, {10071, 0xD106}, {10072, 0xD107}, {10073, 0xD108},
    {10074, 0xD109}, {10075, 0xD10A}, {10076, 0xD10B}, {10077, 0xD10C},
    {10078, 0xD10E}, {10079, 0xD10F}, {10080, 0xD110}, {10081, 0xD111},
    {10082, 0xD112}, {10083, 0xD113}, {10084, 0xD114}, {10085, 0xD115},
    {10086, 0xD116}, {10087, 0xD117}, {10088, 0xD118}, {10089, 0xD119},
    {10090, 0xD11A}, {10091, 0xD11B}, {10092, 0xD11C}, {10093, 0xD11D},
    {10094, 0xD11E}, {10095, 0xD11F}, {10102, 0xD120}, {10103, 0xD121},
    {10104, 0xD122}, {10105, 0xD123}, {10106, 0xD124}, {10107, 0xD125},
    {10108, 0xD126}, {10109, 0xD127}, {10110, 0xD128}, {10111, 0xD129},
    {10112, 0xD12A}, {10113, 0xD12B}, {10114, 0xD12C}, {10115, 0xD12D},
    {10116, 0xD12E}, {10117, 0xD12F}, {10118, 0xD132}, {10119, 0xD133},
    {10120, 0xD135}, {10121, 0xD136}, {10122, 0xD137}, {10123, 0xD139},
    {10124, 0xD13B}, {10125, 0xD13C}, {10126, 0xD13D}, {10127, 0xD13E},
    {10134, 0xD13F}, {10135, 0xD142}, {10136, 0xD146}, {10137, 0xD147},
    {10138, 0xD148}, {10139, 0xD149}, {10140, 0xD14A}, {10141, 0xD14B},
    {10142, 0xD14E}, {10143, 0xD14F}, {10144, 0xD151}, {10145, 0xD152},
    {10146, 0xD153}, {10147, 0xD155}, {10148, 0xD156}, {10149, 0xD157},
    {10150, 0xD158}, {10151, 0xD159}, {10152, 0xD15A}, {10153, 0xD15B},
    {10154, 0xD15E}, {10155, 0xD160}, {10156, 0xD162}, {10157, 0xD163},
    {10158, 0xD164}, {10159, 0xD165}, {10160, 0xD166}, {10161, 0xD167},
    {10162, 0xD169}, {10163, 0xD16A}, {10164, 0xD16B}, {10165, 0xD16D},
    {10166, 0xB540}, {10167, 0xB541}, {10168, 0xB543}, {10169, 0xB544},
    {10170, 0xB545}, {10171, 0xB54B}, {10172, 0xB54C}, {10173, 0xB54D},
    {10174, 0xB550}, {10175, 0xB554}, {10176, 0xB55C}, {10177, 0xB55D},
    {10178, 0xB55F}, {10179, 0xB560}, {10180, 0xB561}, {10181, 0xB5A0},
    {10182, 0xB5A1}, {10183, 0xB5A4}, {10184, 0xB5A8}, {10185, 0xB5AA},
    {10186, 0xB5AB}, {10187, 0xB5B0}, {10188, 0xB5B1}, {10189, 0xB5B3},
    {10190, 0xB5B4}, {10191, 0xB5B5}, {10192, 0xB5BB}, {10193, 0xB5BC},
    {10194, 0xB5BD}, {10195, 0xB5C0}, {10196, 0xB5C4}, {10197, 0xB5CC},
    {10198, 0xB5CD}, {10199, 0xB5CF}, {10200, 0xB5D0}, {10201, 0xB5D1},
    {10202, 0xB5D8}, {10203, 0xB5EC}, {10204, 0xB610}, {10205, 0xB611},
    {10206, 0xB614}, {10207, 0xB618}, {10208, 0xB625}, {10209, 0xB62C},
    {10210, 0xB634}, {10211, 0xB648}, {10212, 0xB664}, {10213, 0xB668},
    {10214, 0xB69C}, {10215, 0xB69D}, {10216, 0xB6A0}, {10217, 0xB6A4},
    {10218, 0xB6AB}, {10219, 0xB6AC}, {10220, 0xB6B1}, {10221, 0xB6D4},
    {10222, 0xB6F0}, {10223, 0xB6F4}, {10224, 0xB6F8}, {10225, 0xB700},
    {10226, 0xB701}, {10227, 0xB705}, {10228, 0xB728}, {10229, 0xB729},
    {10230, 0xB72C}, {10231, 0xB72F}, {10232, 0xB730}, {10233, 0xB738},
    {10234, 0xB739}, {10235, 0xB73B}, {10236, 0xB744}, {10237, 0xB748},
    {10238, 0xB74C}, {10239, 0xB754}, {10240, 0xB755}, {10241, 0xB760},
    {10242, 0xB764}, {10243, 0xB768}, {10244, 0xB770}, {10245, 0xB771},
    {10246, 0xB773}, {10247, 0xB775}, {10248, 0xB77C}, {10249, 0xB77D},
    {10250, 0xB780}, {10251, 0xB784}, {10252, 0xB78C}, {10253, 0xB78D},
    {10254, 0xB78F}, {10255, 0xB790}, {10256, 0xB791}, {10257, 0xB792},
    {10258, 0xB796}, {10259, 0xB797}, {10260, 0xD16E}, {10261, 0xD16F},
    {10262, 0xD170}, {10263, 0xD171}, {10264, 0xD172}, {10265, 0xD173},
    {10266, 0xD174}, {10267, 0xD175}, {10268, 0xD176}, {10269, 0xD177},
    {10270, 0xD178}, {10271, 0xD179}, {10272, 0xD17A}, {10273, 0xD17B},
    {10274, 0xD17D}, {10275, 0xD17E}, {10276, 0xD17F}, {10277, 0xD180},
    {10278, 0xD181}, {10279, 0xD182}, {10280, 0xD183}, {10281, 0xD185},
    {10282, 0xD186}, {10283, 0xD187}, {10284, 0xD189}, {10285, 0xD18A},
    {10292, 0xD18B}, {10293, 0xD18C}, {10294, 0xD18D}, {10295, 0xD18E},
    {10296, 0xD18F}, {10297, 0xD190}, {10298, 0xD191}, {10299, 0xD192},
    {10300, 0xD193}, {10301, 0xD194}, {10302, 0xD195}, {10303, 0xD196},
    {10304, 0xD197}, {10305, 0xD198}, {10306, 0xD199}, {10307, 0xD19A},
    {10308, 0xD19B}, {10309, 0xD19C}, {10310, 0xD19D}, {10311, 0xD19E},
    {10312, 0xD19F}, {10313, 0xD1A2}, {10314, 0xD1A3}, {10315, 0xD1A5},
    {10316, 0xD1A6}, {10317, 0xD1A7}, {10324, 0xD1A9}, {10325, 0xD1AA},
    {10326, 0xD1AB}, {10327, 0xD1AC}, {10328, 0xD1AD}, {10329, 0xD1AE},
    {10330, 0xD1AF}, {10331, 0xD1B2}, {10332, 0xD1B4}, {10333, 0xD1B6},
    {10334, 0xD1B7}, {10335, 0xD1B8}, {10336, 0xD1B9}, {10337, 0xD1BB},
    {10338, 0xD1BD}, {10339, 0xD1BE}, {10340, 0xD1BF}, {10341, 0xD1C1},
    {10342, 0xD1C2}, {10343, 0xD1C3}, {10344, 0xD1C4}, {10345, 0xD1C5},
    {10346, 0xD1C6}, {10347, 0xD1C7}, {10348, 0xD1C8}, {10349, 0xD1C9},
    {10350, 0xD1CA}, {10351, 0xD1CB}, {10352, 0xD1CC}, {10353, 0xD1CD},
    {10354, 0xD1CE}, {10355, 0xD1CF}, {10356, 0xB798}, {10357, 0xB799},
    {10358, 0xB79C}, {10359, 0xB7A0}, {10360, 0xB7A8}, {10361, 0xB7A9},
    {10362, 0xB7AB}, {10363, 0xB7AC}, {10364, 0xB7AD}, {10365, 0xB7B4},
    {10366, 0xB7B5}, {10367, 0xB7B8}, {10368, 0xB7C7}, {10369, 0xB7C9},
    {10370, 0xB7EC}, {10371, 0xB7ED}, {10372, 0xB7F0}, {10373, 0xB7F4},
    {10374, 0xB7FC}, {10375, 0xB7FD}, {10376, 0xB7FF}, {10377, 0xB800},
    {10378, 0xB801}, {10379, 0xB807}, {10380, 0xB808}, {10381, 0xB809},
    {10382, 0xB80C}, {10383, 0xB810}, {10384, 0xB818}, {10385, 0xB819},
    {10386, 0xB81B}, {10387, 0xB81D}, {10388, 0xB824}, {10389, 0xB825},
    {10390, 0xB828}, {10391, 0xB82C}, {10392, 0xB834}, {10393, 0xB835},
    {10394, 0xB837}, {10395, 0xB838}, {10396, 0xB839}, {10397, 0xB840},
    {10398, 0xB844}, {10399, 0xB851}, {10400, 0xB853}, {10401, 0xB85C},
    {10402, 0xB85D}, {10403, 0xB860}, {10404, 0xB864}, {10405, 0xB86C},
    {10406, 0xB86D}, {10407, 0xB86F}, {10408, 0xB871}, {10409, 0xB878},
    {10410, 0xB87C}, {10411, 0xB88D}, {10412, 0xB8A8}, {10413, 0xB8B0},
    {10414, 0xB8B4}, {10415, 0xB8B8}, {10416, 0xB8C0}, {10417, 0xB8C1},
    {10418, 0xB8C3}, {10419, 0xB8C5}, {10420, 0xB8CC}, {10421, 0xB8D0},
    {10422, 0xB8D4}, {10423, 0xB8DD}, {10424, 0xB8DF}, {10425, 0xB8E1},
    {10426, 0xB8E8}, {10427, 0xB8E9}, {10428, 0xB8EC}, {10429, 0xB8F0},
    {10430, 0xB8F8}, {10431, 0xB8F9}, {10432, 0xB8FB}, {10433, 0xB8FD},
    {10434, 0xB904}, {10435, 0xB918}, {10436, 0xB920}, {10437, 0xB93C},
    {10438, 0xB93D}, {10439, 0xB940}, {10440, 0xB944}, {10441, 0xB94C},
    {10442, 0xB94F}, {10443, 0xB951}, {10444, 0xB958}, {10445, 0xB959},
    {10446, 0xB95C}, {10447, 0xB960}, {10448, 0xB968}, {10449, 0xB969},
    {10450, 0xD1D0}, {10451, 0xD1D1}, {10452, 0xD1D2}, {10453, 0xD1D3},
    {10454, 0xD1D4}, {10455, 0xD1D5}, {10456, 0xD1D6}, {10457, 0xD1D7},
    {10458, 0xD1D9}, {10459, 0xD1DA}, {10460, 0xD1DB}, {10461, 0xD1DC},
    {10462, 0xD1DD}, {10463, 0xD1DE}, {10464, 0xD1DF}, {10465, 0xD1E0},
    {10466, 0xD1E1}, {10467, 0xD1E2}, {10468, 0xD1E3}, {10469, 0xD1E4},
    {10470, 0xD1E5}, {10471, 0xD1E6}, {10472, 0xD1E7}, {10473, 0xD1E8},
    {10474, 0xD1E9}, {10475, 0xD1EA}, {10482, 0xD1EB}, {10483, 0xD1EC},
    {10484, 0xD1ED}, {10485, 0xD1EE}, {10486, 0xD1EF}, {10487, 0xD1F0},
    {10488, 0xD1F1}, {10489, 0xD1F2}, {10490, 0xD1F3}, {10491, 0xD1F5},
    {10492, 0xD1F6}, {10493, 0xD1F7}, {10494, 0xD1F9}, {10495, 0xD1FA},
    {10496, 0xD1FB}, {10497, 0xD1FC}, {10498, 0xD1FD}, {10499, 0xD1FE},
    {10500, 0xD1FF}, {10501, 0xD200}, {10502, 0xD201}, {10503, 0xD202},
    {10504, 0xD203}, {10505, 0xD204}, {10506, 0xD205}, {10507, 0xD206},
    {10514, 0xD208}, {10515, 0xD20A}, {10516, 0xD20B}, {10517, 0xD20C},
    {10518, 0xD20D}, {10519, 0xD20E}, {10520, 0xD20F}, {10521, 0xD211},
    {10522, 0xD212}, {10523, 0xD213}, {10524, 0xD214}, {10525, 0xD215},
    {10526, 0xD216}, {10527, 0xD217}, {10528, 0xD218}, {10529, 0xD219},
    {10530, 0xD21A}, {10531, 0xD21B}, {10532, 0xD21C}, {10533, 0xD21D},
    {10534, 0xD21E}, {10535, 0xD21F}, {10536, 0xD220}, {10537, 0xD221},
    {10538, 0xD222}, {10539, 0xD223}, {10540, 0xD224}, {10541, 0xD225},
    {10542, 0xD226}, {10543, 0xD227}, {10544, 0xD228}, {10545, 0xD229},
    {10546, 0xB96B}, {10547, 0xB96D}, {10548, 0xB974}, {10549, 0xB975},
    {10550, 0xB978}, {10551, 0xB97C}, {10552, 0xB984}, {10553, 0xB985},
    {10554, 0xB987}, {10555, 0xB989}, {10556, 0xB98A}, {10557, 0xB98D},
    {10558, 0xB98E}, {10559, 0xB9AC}, {10560, 0xB9AD}, {10561, 0xB9B0},
    {10562, 0xB9B4}, {10563, 0xB9BC}, {10564, 0xB9BD}, {10565, 0xB9BF},
    {10566, 0xB9C1}, {10567, 0xB9C8}, {10568, 0xB9C9}, {10569, 0xB9CC},
    {10570, 0xB9CE}, {10571, 0xB9CF}, {10572, 0xB9D0}, {10573, 0xB9D1},
    {10574, 0xB9D2}, {10575, 0xB9D8}, {10576, 0xB9D9}, {10577, 0xB9DB},
    {10578, 0xB9DD}, {10579, 0xB9DE}, {10580, 0xB9E1}, {10581, 0xB9E3},
    {10582, 0xB9E4}, {10583, 0xB9E5}, {10584, 0xB9E8}, {10585, 0xB9EC},
    {10586, 0xB9F4}, {10587, 0xB9F5}, {10588, 0xB9F7}, {10589, 0xB9F8},
    {10590, 0xB9F9}, {10591, 0xB9FA}, {10592, 0xBA00}, {10593, 0xBA01},
    {10594, 0xBA08}, {10595, 0xBA15}, {10596, 0xBA38}, {10597, 0xBA39},
    {10598, 0xBA3C}, {10599, 0xBA40}, {10600, 0xBA42}, {10601, 0xBA48},
    {10602, 0xBA49}, {10603, 0xBA4B}, {10604, 0xBA4D}, {10605, 0xBA4E},
    {10606, 0xBA53}, {10607, 0xBA54}, {10608, 0xBA55}, {10609, 0xBA58},
    {10610, 0xBA5C}, {10611, 0xBA64}, {10612, 0xBA65}, {10613, 0xBA67},
    {10614, 0xBA68}, {10615, 0xBA69}, {10616, 0xBA70}, {10617, 0xBA71},
    {10618, 0xBA74}, {10619, 0xBA78}, {10620, 0xBA83}, {10621, 0xBA84},
    {10622, 0xBA85}, {10623, 0xBA87}, {10624, 0xBA8C}, {10625, 0xBAA8},
    {10626, 0xBAA9}, {10627, 0xBAAB}, {10628, 0xBAAC}, {10629, 0xBAB0},
    {10630, 0xBAB2}, {10631, 0xBAB8}, {10632, 0xBAB9}, {10633, 0xBABB},
    {10634, 0xBABD}, {10635, 0xBAC4}, {10636, 0xBAC8}, {10637, 0xBAD8},
    {10638, 0xBAD9}, {10639, 0xBAFC}, {10640, 0xD22A}, {10641, 0xD22B},
    {10642, 0xD22E}, {10643, 0xD22F}, {10644, 0xD231}, {10645, 0xD232},
    {10646, 0xD233}, {10647, 0xD235}, {10648, 0xD236}, {10649, 0xD237},
    {10650, 0xD238}, {10651, 0xD239}, {10652, 0xD23A}, {10653, 0xD23B},
    {10654, 0xD23E}, {10655, 0xD240}, {10656, 0xD242}, {10657, 0xD243},
    {10658, 0xD244}, {10659, 0xD245}, {10660, 0xD246}, {10661, 0xD247},
    {10662, 0xD249}, {10663, 0xD24A}, {10664, 0xD24B}, {10665, 0xD24C},
    {10672, 0xD24D}, {10673, 0xD24E}, {10674, 0xD24F}, {10675, 0xD250},
    {10676, 0xD251}, {10677, 0xD252}, {10678, 0xD253}, {10679, 0xD254},
    {10680, 0xD255}, {10681, 0xD256}, {10682, 0xD257}, {10683, 0xD258},
    {10684, 0xD259}, {10685, 0xD25A}, {10686, 0xD25B}, {10687, 0xD25D},
    {10688, 0xD25E}, {10689, 0xD25F}, {10690, 0xD260}, {10691, 0xD261},
    {10692, 0xD262}, {10693, 0xD263}, {10694, 0xD265}, {10695, 0xD266},
    {10696, 0xD267}, {10697, 0xD268}, {10704, 0xD269}, {10705, 0xD26A},
    {10706, 0xD26B}, {10707, 0xD26C}, {10708, 0xD26D}, {10709, 0xD26E},
    {10710, 0xD26F}, {10711, 0xD270}, {10712, 0xD271}, {10713, 0xD272},
    {10714, 0xD273}, {10715, 0xD274}, {10716, 0xD275}, {10717, 0xD276},
    {10718, 0xD277}, {10719, 0xD278}, {10720, 0xD279}, {10721, 0xD27A},
    {10722, 0xD27B}, {10723, 0xD27C}, {10724, 0xD27D}, {10725, 0xD27E},
    {10726, 0xD27F}, {10727, 0xD282}, {10728, 0xD283}, {10729, 0xD285},
    {10730, 0xD286}, {10731, 0xD287}, {10732, 0xD289}, {10733, 0xD28A},
    {10734, 0xD28B}, {10735, 0xD28C}, {10736, 0xBB00}, {10737, 0xBB04},
    {10738, 0xBB0D}, {10739, 0xBB0F}, {10740, 0xBB11}, {10741, 0xBB18},
    {10742, 0xBB1C}, {10743, 0xBB20}, {10744, 0xBB29}, {10745, 0xBB2B},
    {10746, 0xBB34}, {10747, 0xBB35}, {10748, 0xBB36}, {10749, 0xBB38},
    {10750, 0xBB3B}, {10751, 0xBB3C}, {10752, 0xBB3D}, {10753, 0xBB3E},
    {10754, 0xBB44}, {10755, 0xBB45}, {10756, 0xBB47}, {10757, 0xBB49},
    {10758, 0xBB4D}, {10759, 0xBB4F}, {10760, 0xBB50}, {10761, 0xBB54},
    {10762, 0xBB58}, {10763, 0xBB61}, {10764, 0xBB63}, {10765, 0xBB6C},
    {10766, 0xBB88}, {10767, 0xBB8C}, {10768, 0xBB90}, {10769, 0xBBA4},
    {10770, 0xBBA8}, {10771, 0xBBAC}, {10772, 0xBBB4}, {10773, 0xBBB7},
    {10774, 0xBBC0}, {10775, 0xBBC4}, {10776, 0xBBC8}, {10777, 0xBBD0},
    {10778, 0xBBD3}, {10779, 0xBBF8}, {10780, 0xBBF9}, {10781, 0xBBFC},
    {10782, 0xBBFF}, {10783, 0xBC00}, {10784, 0xBC02}, {10785, 0xBC08},
    {10786, 0xBC09}, {10787, 0xBC0B}, {10788, 0xBC0C}, {10789, 0xBC0D},
    {10790, 0xBC0F}, {10791, 0xBC11}, {10792, 0xBC14}, {10793, 0xBC15},
    {10794, 0xBC16}, {10795, 0xBC17}, {10796, 0xBC18}, {10797, 0xBC1B},
    {10798, 0xBC1C}, {10799, 0xBC1D}, {10800, 0xBC1E}, {10801, 0xBC1F},
    {10802, 0xBC24}, {10803, 0xBC25}, {10804, 0xBC27}, {10805, 0xBC29},
    {10806, 0xBC2D}, {10807, 0xBC30}, {10808, 0xBC31}, {10809, 0xBC34},
    {10810, 0xBC38}, {10811, 0xBC40}, {10812, 0xBC41}, {10813, 0xBC43},
    {10814, 0xBC44}, {10815, 0xBC45}, {10816, 0xBC49}, {10817, 0xBC4C},
    {10818, 0xBC4D}, {10819, 0xBC50}, {10820, 0xBC5D}, {10821, 0xBC84},
    {10822, 0xBC85}, {10823, 0xBC88}, {10824, 0xBC8B}, {10825, 0xBC8C},
    {10826, 0xBC8E}, {10827, 0xBC94}, {10828, 0xBC95}, {10829, 0xBC97},
    {10830, 0xD28D}, {10831, 0xD28E}, {10832, 0xD28F}, {10833, 0xD292},
    {10834, 0xD293}, {10835, 0xD294}, {10836, 0xD296}, {10837, 0xD297},
    {10838, 0xD298}, {10839, 0xD299}, {10840, 0xD29A}, {10841, 0xD29B},
    {10842, 0xD29D}, {10843, 0xD29E}, {10844, 0xD29F}, {10845, 0xD2A1},
    {10846, 0xD2A2}, {10847, 0xD2A3}, {10848, 0xD2A5}, {10849, 0xD2A6},
    {10850, 0xD2A7}, {10851, 0xD2A8}, {10852, 0xD2A9}, {10853, 0xD2AA},
    {10854, 0xD2AB}, {10855, 0xD2AD}, {10862, 0xD2AE}, {10863, 0xD2AF},
    {10864, 0xD2B0}, {10865, 0xD2B2}, {10866, 0xD2B3}, {10867, 0xD2B4},
    {10868, 0xD2B5}, {10869, 0xD2B6}, {10870, 0xD2B7}, {10871, 0xD2BA},
    {10872, 0xD2BB}, {10873, 0xD2BD}, {10874, 0xD2BE}, {10875, 0xD2C1},
    {10876, 0xD2C3}, {10877, 0xD2C4}, {10878, 0xD2C5}, {10879, 0xD2C6},
    {10880, 0xD2C7}, {10881, 0xD2CA}, {10882, 0xD2CC}, {10883, 0xD2CD},
    {10884, 0xD2CE}, {10885, 0xD2CF}, {10886, 0xD2D0}, {10887, 0xD2D1},
    {10894, 0xD2D2}, {10895, 0xD2D3}, {10896, 0xD2D5}, {10897, 0xD2D6},
    {10898, 0xD2D7}, {10899, 0xD2D9}, {10900, 0xD2DA}, {10901, 0xD2DB},
    {10902, 0xD2DD}, {10903, 0xD2DE}, {10904, 0xD2DF}, {10905, 0xD2E0},
    {10906, 0xD2E1}, {10907, 0xD2E2}, {10908, 0xD2E3}, {10909, 0xD2E6},
    {10910, 0xD2E7}, {10911, 0xD2E8}, {10912, 0xD2E9}, {10913, 0xD2EA},
    {10914, 0xD2EB}, {10915, 0xD2EC}, {10916, 0xD2ED}, {10917, 0xD2EE},
    {10918, 0xD2EF}, {10919, 0xD2F2}, {10920, 0xD2F3}, {10921, 0xD2F5},
    {10922, 0xD2F6}, {10923, 0xD2F7}, {10924, 0xD2F9}, {10925, 0xD2FA},
    {10926, 0xBC99}, {10927, 0xBC9A}, {10928, 0xBCA0}, {10929, 0xBCA1},
    {10930, 0xBCA4}, {10931, 0xBCA7}, {10932, 0xBCA8}, {10933, 0xBCB0},
    {10934, 0xBCB1}, {10935, 0xBCB3}, {10936, 0xBCB4}, {10937, 0xBCB5},
    {10938, 0xBCBC}, {10939, 0xBCBD}, {10940, 0xBCC0}, {10941, 0xBCC4},
    {10942, 0xBCCD}, {10943, 0xBCCF}, {10944, 0xBCD0}, {10945, 0xBCD1},
    {10946, 0xBCD5}, {10947, 0xBCD8}, {10948, 0xBCDC}, {10949, 0xBCF4},
    {10950, 0xBCF5}, {10951, 0xBCF6}, {10952, 0xBCF8}, {10953, 0xBCFC},
    {10954, 0xBD04}, {10955, 0xBD05}, {10956, 0xBD07}, {10957, 0xBD09},
    {10958, 0xBD10}, {10959, 0xBD14}, {10960, 0xBD24}, {10961, 0xBD2C},
    {10962, 0xBD40}, {10963, 0xBD48}, {10964, 0xBD49}, {10965, 0xBD4C},
    {10966, 0xBD50}, {10967, 0xBD58}, {10968, 0xBD59}, {10969, 0xBD64},
    {10970, 0xBD68}, {10971, 0xBD80}, {10972, 0xBD81}, {10973, 0xBD84},
    {10974, 0xBD87}, {10975, 0xBD88}, {10976, 0xBD89}, {10977, 0xBD8A},
    {10978, 0xBD90}, {10979, 0xBD91}, {10980, 0xBD93}, {10981, 0xBD95},
    {10982, 0xBD99}, {10983, 0xBD9A}, {10984, 0xBD9C}, {10985, 0xBDA4},
    {10986, 0xBDB0}, {10987, 0xBDB8}, {10988, 0xBDD4}, {10989, 0xBDD5},
    {10990, 0xBDD8}, {10991, 0xBDDC}, {10992, 0xBDE9}, {10993, 0xBDF0},
    {10994, 0xBDF4}, {10995, 0xBDF8}, {10996, 0xBE00}, {10997, 0xBE03},
    {10998, 0xBE05}, {10999, 0xBE0C}, {11000, 0xBE0D}, {11001, 0xBE10},
    {11002, 0xBE14}, {11003, 0xBE1C}, {11004, 0xBE1D}, {11005, 0xBE1F},
    {11006, 0xBE44}, {11007, 0xBE45}, {11008, 0xBE48}, {11009, 0xBE4C},
    {11010, 0xBE4E}, {11011, 0xBE54}, {11012, 0xBE55}, {11013, 0xBE57},
    {11014, 0xBE59}, {11015, 0xBE5A}, {11016, 0xBE5B}, {11017, 0xBE60},
    {11018, 0xBE61}, {11019, 0xBE64}, {11020, 0xD2FB}, {11021, 0xD2FC},
    {11022, 0xD2FD}, {11023, 0xD2FE}, {11024, 0xD2FF}, {11025, 0xD302},
    {11026, 0xD304}, {11027, 0xD306}, {11028, 0xD307}, {11029, 0xD308},
    {11030, 0xD309}, {11031, 0xD30A}, {11032, 0xD30B}, {11033, 0xD30F},
    {11034, 0xD311}, {11035, 0xD312}, {11036, 0xD313}, {11037, 0xD315},
    {11038, 0xD317}, {11039, 0xD318}, {11040, 0xD319}, {11041, 0xD31A},
    {11042, 0xD31B}, {11043, 0xD31E}, {11044, 0xD322}, {11045, 0xD323},
    {11052, 0xD324}, {11053, 0xD326}, {11054, 0xD327}, {11055, 0xD32A},
    {11056, 0xD32B}, {11057, 0xD32D}, {11058, 0xD32E}, {11059, 0xD32F},
    {11060, 0xD331}, {11061, 0xD332}, {11062, 0xD333}, {11063, 0xD334},
    {11064, 0xD335}, {11065, 0xD336}, {11066, 0xD337}, {11067, 0xD33A},
    {11068, 0xD33E}, {11069, 0xD33F}, {11070, 0xD340}, {11071, 0xD341},
    {11072, 0xD342}, {11073, 0xD343}, {11074, 0xD346}, {11075, 0xD347},
    {11076, 0xD348}, {11077, 0xD349}, {11084, 0xD34A}, {11085, 0xD34B},
    {11086, 0xD34C}, {11087, 0xD34D}, {11088, 0xD34E}, {11089, 0xD34F},
    {11090, 0xD350}, {11091, 0xD351}, {11092, 0xD352}, {11093, 0xD353},
    {11094, 0xD354}, {11095, 0xD355}, {11096, 0xD356}, {11097, 0xD357},
    {11098, 0xD358}, {11099, 0xD359}, {11100, 0xD35A}, {11101, 0xD35B},
    {11102, 0xD35C}, {11103, 0xD35D}, {11104, 0xD35E}, {11105, 0xD35F},
    {11106, 0xD360}, {11107, 0xD361}, {11108, 0xD362}, {11109, 0xD363},
    {11110, 0xD364}, {11111, 0xD365}, {11112, 0xD366}, {11113, 0xD367},
    {11114, 0xD368}, {11115, 0xD369}, {11116, 0xBE68}, {11117, 0xBE6A},
    {11118, 0xBE70}, {11119, 0xBE71}, {11120, 0xBE73}, {11121, 0xBE74},
    {11122, 0xBE75}, {11123, 0xBE7B}, {11124, 0xBE7C}, {11125, 0xBE7D},
    {11126, 0xBE80}, {11127, 0xBE84}, {11128, 0xBE8C}, {11129, 0xBE8D},
    {11130, 0xBE8F}, {11131, 0xBE90}, {11132, 0xBE91}, {11133, 0xBE98},
    {11134, 0xBE99}, {11135, 0xBEA8}, {11136, 0xBED0}, {11137, 0xBED1},
    {11138, 0xBED4}, {11139, 0xBED7}, {11140, 0xBED8}, {11141, 0xBEE0},
    {11142, 0xBEE3}, {11143, 0xBEE4}, {11144, 0xBEE5}, {11145, 0xBEEC},
    {11146, 0xBF01}, {11147, 0xBF08}, {11148, 0xBF09}, {11149, 0xBF18},
    {11150, 0xBF19}, {11151, 0xBF1B}, {11152, 0xBF1C}, {11153, 0xBF1D},
    {11154, 0xBF40}, {11155, 0xBF41}, {11156, 0xBF44}, {11157, 0xBF48},
    {11158, 0xBF50}, {11159, 0xBF51}, {11160, 0xBF55}, {11161, 0xBF94},
    {11162, 0xBFB0}, {11163, 0xBFC5}, {11164, 0xBFCC}, {11165, 0xBFCD},
    {11166, 0xBFD0}, {11167, 0xBFD4}, {11168, 0xBFDC}, {11169, 0xBFDF},
    {11170, 0xBFE1}, {11171, 0xC03C}, {11172, 0xC051}, {11173, 0xC058},
    {11174, 0xC05C}, {11175, 0xC060}, {11176, 0xC068}, {11177, 0xC069},
    {11178, 0xC090}, {11179, 0xC091}, {11180, 0xC094}, {11181, 0xC098},
    {11182, 0xC0A0}, {11183, 0xC0A1}, {11184, 0xC0A3}, {11185, 0xC0A5},
    {11186, 0xC0AC}, {11187, 0xC0AD}, {11188, 0xC0AF}, {11189, 0xC0B0},
    {11190, 0xC0B3}, {11191, 0xC0B4}, {11192, 0xC0B5}, {11193, 0xC0B6},
    {11194, 0xC0BC}, {11195, 0xC0BD}, {11196, 0xC0BF}, {11197, 0xC0C0},
    {11198, 0xC0C1}, {11199, 0xC0C5}, {11200, 0xC0C8}, {11201, 0xC0C9},
    {11202, 0xC0CC}, {11203, 0xC0D0}, {11204, 0xC0D8}, {11205, 0xC0D9},
    {11206, 0xC0DB}, {11207, 0xC0DC}, {11208, 0xC0DD}, {11209, 0xC0E4},
    {11210, 0xD36A}, {11211, 0xD36B}, {11212, 0xD36C}, {11213, 0xD36D},
    {11214, 0xD36E}, {11215, 0xD36F}, {11216, 0xD370}, {11217, 0xD371},
    {11218, 0xD372}, {11219, 0xD373}, {11220, 0xD374}, {11221, 0xD375},
    {11222, 0xD376}, {11223, 0xD377}, {11224, 0xD378}, {11225, 0xD379},
    {11226, 0xD37A}, {11227, 0xD37B}, {11228, 0xD37E}, {11229, 0xD37F},
    {11230, 0xD381}, {11231, 0xD382}, {11232, 0xD383}, {11233, 0xD385},
    {11234, 0xD386}, {11235, 0xD387}, {11242, 0xD388}, {11243, 0xD389},
    {11244, 0xD38A}, {11245, 0xD38B}, {11246, 0xD38E}, {11247, 0xD392},
    {11248, 0xD393}, {11249, 0xD394}, {11250, 0xD395}, {11251, 0xD396},
    {11252, 0xD397}, {11253, 0xD39A}, {11254, 0xD39B}, {11255, 0xD39D},
    {11256, 0xD39E}, {11257, 0xD39F}, {11258, 0xD3A1}, {11259, 0xD3A2},
    {11260, 0xD3A3}, {11261, 0xD3A4}, {11262, 0xD3A5}, {11263, 0xD3A6},
    {11264, 0xD3A7}, {11265, 0xD3AA}, {11266, 0xD3AC}, {11267, 0xD3AE},
    {11274, 0xD3AF}, {11275, 0xD3B0}, {11276, 0xD3B1}, {11277, 0xD3B2},
    {11278, 0xD3B3}, {11279, 0xD3B5}, {11280, 0xD3B6}, {11281, 0xD3B7},
    {11282, 0xD3B9}, {11283, 0xD3BA}, {11284, 0xD3BB}, {11285, 0xD3BD},
    {11286, 0xD3BE}, {11287, 0xD3BF}, {11288, 0xD3C0}, {11289, 0xD3C1},
    {11290, 0xD3C2}, {11291, 0xD3C3}, {11292, 0xD3C6}, {11293, 0xD3C7},
    {11294, 0xD3CA}, {11295, 0xD3CB}, {11296, 0xD3CC}, {11297, 0xD3CD},
    {11298, 0xD3CE}, {11299, 0xD3CF}, {11300, 0xD3D1}, {11301, 0xD3D2},
    {11302, 0xD3D3}, {11303, 0xD3D4}, {11304, 0xD3D5}, {11305, 0xD3D6},
    {11306, 0xC0E5}, {11307, 0xC0E8}, {11308, 0xC0EC}, {11309, 0xC0F4},
    {11310, 0xC0F5}, {11311, 0xC0F7}, {11312, 0xC0F9}, {11313,
```