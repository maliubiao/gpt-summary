Response:
Let's break down the thought process for analyzing this code snippet.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a C++ source code file related to Unicode string handling in V8. It specifically mentions checking for Torque origins (.tq) and connections to JavaScript. The core task is to summarize the functionality of the provided code block (the second of six parts).

**2. High-Level Overview of the Code:**

The immediate observation is that the code consists of several `static const` arrays and functions. The array names like `kID_StartTableX`, `kID_ContinueTableX`, `kWhiteSpaceTableX`, `kToLowercaseTableX`, and `kToUppercaseTableX` strongly suggest that these arrays hold data related to different Unicode properties. The function names like `ID_Start::Is`, `ID_Continue::Is`, `WhiteSpace::Is`, `ToLowercase::Convert`, and `ToUppercase::Convert` further reinforce this idea – they appear to be predicate or conversion functions based on these tables.

**3. Analyzing Individual Code Sections:**

* **`ID_Start` and `ID_Continue`:** The comments above these sections mention Unicode categories and properties. Specifically, `ID_Start` relates to characters that can begin an identifier, and `ID_Continue` relates to characters that can continue an identifier. The `Is(uchar c)` functions within these structs use a `LookupPredicate` function (not shown but assumed to be defined elsewhere) to check if a given character `c` belongs to the respective category. The `chunk_index` and `switch` statement suggest a way of efficiently indexing into the large tables based on the character's value.

* **`WhiteSpace`:** This section is similar to the identifier sections. It checks if a character belongs to the "WhiteSpace" category using a lookup table.

* **`ToLowercase` and `ToUppercase`:** These sections are more complex. They have `Convert` functions instead of `Is` functions, indicating a transformation rather than a simple boolean check. They also introduce `MultiCharacterSpecialCase` arrays. This suggests that some Unicode characters might have multi-character lowercase or uppercase equivalents (e.g., the German lowercase sharp S "ß" uppercases to "SS"). The `LookupMapping` function (again, assumed to be defined elsewhere) likely handles both simple single-character and these multi-character mappings. The `allow_caching_ptr` argument hints at potential optimization through caching of conversion results.

**4. Inferring Functionality and Purpose:**

Based on the array names, comments, and function signatures, the primary function of this code block appears to be:

* **Unicode Property Lookups:**  Efficiently determining if a given Unicode character has certain properties (e.g., can start an identifier, can continue an identifier, is whitespace). This is done using precomputed lookup tables for performance.
* **Unicode Case Conversion:**  Converting Unicode characters to their lowercase and uppercase equivalents, including handling cases where a single character maps to multiple characters.

**5. Connecting to JavaScript (If Applicable):**

The names "JS_ID_Continue" and "JS_White_Space" in the comments directly link this code to JavaScript. These properties are used to define what constitutes a valid identifier and whitespace in JavaScript.

* **JavaScript Identifier Example:**  In JavaScript, variable names must start with a letter, underscore (_), or dollar sign ($), and subsequent characters can include digits. The `ID_Start` and `ID_Continue` checks in the C++ code are directly used to implement this rule in the V8 engine.

* **JavaScript Whitespace Example:** JavaScript recognizes various whitespace characters, including spaces, tabs, and line breaks. The `WhiteSpace::Is` function implements the logic to identify these characters.

**6. Code Logic Inference and Assumptions:**

* **LookupPredicate:** Assumes this function takes a table, its size, and a character as input and returns `true` if the character is present in the table (or within the ranges defined by the table). The table structure likely uses pairs of values to represent ranges.
* **LookupMapping:** Assumes this function takes a table, its size, a multi-character special case array, the input character, the next character (for context-sensitive conversions), a result buffer, and a pointer to a boolean for caching. It returns the number of characters in the lowercase/uppercase equivalent.
* **Table Structure:**  The tables likely store pairs of integers. For predicate checks, these pairs probably represent ranges (start and end code points). For mappings, they might store the original character and its lowercase/uppercase equivalent (or a pointer to a multi-character equivalent). The negative values in the `ToLowercaseTable0` likely indicate an offset to find the lowercase mapping.

**7. Identifying Potential Programming Errors (If Applicable):**

While the provided code is data, the *usage* of such code in a larger context could lead to errors. For example:

* **Incorrectly assuming ASCII:** Developers might incorrectly assume that only ASCII characters need special handling for case conversion or identifier validation, leading to bugs when dealing with non-ASCII Unicode.
* **Forgetting multi-character conversions:** When converting to uppercase, developers might not allocate enough space for the output buffer if a single lowercase character can map to multiple uppercase characters.

**8. Summarizing the Functionality for Part 2:**

Given that this is part 2 of 6, the summary should focus on the functionality present *in this specific code block*. It should highlight the Unicode property checks for identifiers and whitespace, and the case conversion mechanisms with the handling of multi-character mappings. Avoid speculating too much about the other parts of the file.

**Self-Correction/Refinement During the Process:**

* Initially, I might have just said "handles Unicode properties."  However, realizing the explicit mentions of `ID_Start`, `ID_Continue`, and `WhiteSpace` allows for a more specific and accurate description.
*  Seeing the `MultiCharacterSpecialCase` arrays prompted a deeper look into the `ToLowercase` and `ToUppercase` sections, leading to the understanding of multi-character mappings.
* Recognizing "JS_ID_Continue" and "JS_White_Space" is crucial for establishing the connection to JavaScript.

By following this detailed thought process, we can arrive at a comprehensive and accurate analysis of the provided code snippet.
根据您提供的代码片段，这是 `v8/src/strings/unicode.cc` 文件的第二部分，它主要定义了用于判断 Unicode 字符属性（如是否是标识符的起始字符、是否是标识符的后续字符、是否是空白字符）以及进行大小写转换的数据结构和函数。

以下是它的功能归纳：

**核心功能:**

* **Unicode 属性判断:**  定义了静态常量数组 (`kID_StartTableX`, `kID_ContinueTableX`, `kWhiteSpaceTableX`)，这些数组存储了用于快速查找特定 Unicode 字符是否具有特定属性（标识符起始、标识符后续、空白字符）的数据。
* **Unicode 大小写转换:** 定义了静态常量数组 (`kToLowercaseTableX`, `kToUppercaseTableX`) 和 `MultiCharacterSpecialCase` 结构体数组 (`kToLowercaseMultiStringsX`, `kToUppercaseMultiStringsX`)，用于存储 Unicode 字符的大小写映射关系。特别是 `MultiCharacterSpecialCase` 用于处理某些字符转换为大写或小写时需要多个字符的情况。
* **提供判断和转换函数:** 提供了 `Is` 函数（例如 `ID_Start::Is`, `ID_Continue::Is`, `WhiteSpace::Is`) 用于判断字符是否属于特定类别，以及 `Convert` 函数（例如 `ToLowercase::Convert`, `ToUppercase::Convert`) 用于进行大小写转换。

**更具体的功能点:**

1. **标识符起始字符 (ID_Start):**
   -  定义了多个查找表 (`kID_StartTable0` 到 `kID_StartTable7`)，用于快速判断一个 Unicode 字符是否可以作为 JavaScript 标识符的起始字符。
   -  `ID_Start::Is(uchar c)` 函数根据字符 `c` 的值，通过查找相应的表来判断其是否是标识符的起始字符。

2. **标识符后续字符 (ID_Continue):**
   - 定义了多个查找表 (`kID_ContinueTable0`, `kID_ContinueTable1`, `kID_ContinueTable5`, `kID_ContinueTable7`)，用于快速判断一个 Unicode 字符是否可以作为 JavaScript 标识符的后续字符。这通常包括字母、数字、下划线等。
   - `ID_Continue::Is(uchar c)` 函数根据字符 `c` 的值，通过查找相应的表来判断其是否是标识符的后续字符。

3. **空白字符 (WhiteSpace):**
   - 定义了查找表 (`kWhiteSpaceTable0`, `kWhiteSpaceTable1`, `kWhiteSpaceTable7`)，用于快速判断一个 Unicode 字符是否是空白字符。这包括空格、制表符、换行符等。
   - `WhiteSpace::Is(uchar c)` 函数根据字符 `c` 的值，通过查找相应的表来判断其是否是空白字符。

4. **转换为小写 (ToLowercase):**
   - 定义了查找表 (`kToLowercaseTable0`, `kToLowercaseTable1`, `kToLowercaseTable5`, `kToLowercaseTable7`) 和多字符特殊情况表 (`kToLowercaseMultiStrings0`, `kToLowercaseMultiStrings1`, `kToLowercaseMultiStrings5`, `kToLowercaseMultiStrings7`)。
   - `ToLowercase::Convert(uchar c, uchar n, uchar* result, bool* allow_caching_ptr)` 函数将 Unicode 字符 `c` 转换为小写。它可能需要考虑上下文 (`n` 表示下一个字符) 对于某些语言的特殊转换规则。`result` 是存储转换结果的缓冲区，`allow_caching_ptr` 可能用于指示是否允许缓存转换结果。

5. **转换为大写 (ToUppercase):**
   - 定义了查找表 (`kToUppercaseTable0`) 和多字符特殊情况表 (`kToUppercaseMultiStrings0`)。
   - `ToUppercase::Convert(uchar c, uchar n, uchar* result)` 函数将 Unicode 字符 `c` 转换为大写。同样，它可能需要考虑上下文，并使用 `result` 缓冲区存储转换结果。

**与 JavaScript 的关系:**

这段代码直接关系到 JavaScript 的语法解析和字符串处理。

* **标识符:** `ID_Start` 和 `ID_Continue` 的判断逻辑直接决定了哪些字符可以用于命名 JavaScript 中的变量、函数、属性等标识符。
* **空白字符:** `WhiteSpace` 的判断逻辑用于识别 JavaScript 代码中的空白，例如在词法分析阶段分隔不同的 token。
* **大小写转换:** `ToLowercase` 和 `ToUppercase` 的功能被用于实现 JavaScript 字符串的 `toLowerCase()` 和 `toUpperCase()` 方法。

**JavaScript 示例:**

```javascript
// 标识符
let 变量名 = 10; // "变量名" 的字符需要符合 ID_Start 和 ID_Continue 的规则

// 空白字符
let a = 1;
let b = 2; // 空格和换行符是空白字符

// 大小写转换
let str = "HelloWorld";
let lowerStr = str.toLowerCase(); // "helloworld"
let upperStr = str.toUpperCase(); // "HELLOWORLD"
```

**代码逻辑推理:**

假设输入一个 Unicode 字符 `c` 给 `ID_Start::Is(c)` 函数。

* **输入:**  例如，字符 'A' (Unicode 65)。
* **处理:**  `ID_Start::Is` 函数会根据 'A' 的 Unicode 值计算 `chunk_index` (`65 >> 13` 将为 0)。然后，它会调用 `LookupPredicate(kID_StartTable0, kID_StartTable0Size, 65)`。`LookupPredicate` 函数会在 `kID_StartTable0` 中查找是否包含 65 或者包含 65 所在的范围。
* **输出:** 如果在表中找到或在某个范围内，则返回 `true`，表示 'A' 可以作为标识符的起始字符。否则返回 `false`。

**用户常见的编程错误:**

* **假设所有标识符都使用 ASCII 字符:**  用户可能会错误地认为 JavaScript 标识符只能包含英文字母、数字和下划线，而忽略了 Unicode 支持，导致在命名变量时使用了非法的起始字符。

  ```javascript
  // 错误示例 (假设某个 Unicode 字符不在 ID_Start 中)
  let 名字 = "张三"; // 如果 "名" 不在 ID_Start 中，这将导致语法错误
  ```

* **不理解 Unicode 大小写转换的复杂性:**  用户可能会认为简单的转换就是将 ASCII 字符改变大小写，而忽略了某些 Unicode 字符在转换时可能会产生不同的字符甚至多个字符。

  ```javascript
  let str1 = "ﬀ"; // U+FB03 (拉丁文连字 ff)
  let upperStr1 = str1.toUpperCase(); // 可能会得到 "FF" 而不是简单的改变大小写

  let str2 = "ß"; // U+00DF (德语小写字母 sharp s)
  let upperStr2 = str2.toUpperCase(); // 会得到 "SS"
  ```

**归纳一下它的功能 (第2部分):**

这部分代码主要负责定义了 V8 引擎在处理 JavaScript 字符串时用于 **判断 Unicode 字符的标识符属性和空白属性，以及进行 Unicode 字符的大小写转换** 所需的静态数据和查找/转换逻辑。它通过预先计算好的查找表和特殊情况处理，实现了高效的 Unicode 属性判断和大小写转换功能，这对于 JavaScript 引擎的词法分析、语法解析和字符串操作至关重要。

Prompt: 
```
这是目录为v8/src/strings/unicode.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/strings/unicode.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能

"""
      1073746021,
    4198,       1073746030, 4208,       1073746037, 4225,       4238,
    1073746080, 4293,       4295,       4301,       1073746128, 4346,
    1073746172, 4680,       1073746506, 4685,       1073746512, 4694,
    4696,       1073746522, 4701,       1073746528, 4744,       1073746570,
    4749,       1073746576, 4784,       1073746610, 4789,       1073746616,
    4798,       4800,       1073746626, 4805,       1073746632, 4822,
    1073746648, 4880,       1073746706, 4885,       1073746712, 4954,
    1073746816, 5007,       1073746848, 5108,       1073746945, 5740,
    1073747567, 5759,       1073747585, 5786,       1073747616, 5866,
    1073747694, 5880,       1073747712, 5900,       1073747726, 5905,
    1073747744, 5937,       1073747776, 5969,       1073747808, 5996,
    1073747822, 6000,       1073747840, 6067,       6103,       6108,
    1073748000, 6263,       1073748096, 6312,       6314,       1073748144,
    6389,       1073748224, 6430,       1073748304, 6509,       1073748336,
    6516,       1073748352, 6571,       1073748417, 6599,       1073748480,
    6678,       1073748512, 6740,       6823,       1073748741, 6963,
    1073748805, 6987,       1073748867, 7072,       1073748910, 7087,
    1073748922, 7141,       1073748992, 7203,       1073749069, 7247,
    1073749082, 7293,       1073749225, 7404,       1073749230, 7409,
    1073749237, 7414,       1073749248, 7615,       1073749504, 7957,
    1073749784, 7965,       1073749792, 8005,       1073749832, 8013,
    1073749840, 8023,       8025,       8027,       8029,       1073749855,
    8061,       1073749888, 8116,       1073749942, 8124,       8126,
    1073749954, 8132,       1073749958, 8140,       1073749968, 8147,
    1073749974, 8155,       1073749984, 8172,       1073750002, 8180,
    1073750006, 8188};
static const uint16_t kID_StartTable1Size = 84;
static const int32_t kID_StartTable1[84] = {
    113,        127,        1073741968, 156,        258,        263,
    1073742090, 275,        277,        1073742104, 285,        292,
    294,        296,        1073742122, 313,        1073742140, 319,
    1073742149, 329,        334,        1073742176, 392,        1073744896,
    3118,       1073744944, 3166,       1073744992, 3300,       1073745131,
    3310,       1073745138, 3315,       1073745152, 3365,       3367,
    3373,       1073745200, 3431,       3439,       1073745280, 3478,
    1073745312, 3494,       1073745320, 3502,       1073745328, 3510,
    1073745336, 3518,       1073745344, 3526,       1073745352, 3534,
    1073745360, 3542,       1073745368, 3550,       1073745925, 4103,
    1073745953, 4137,       1073745969, 4149,       1073745976, 4156,
    1073745985, 4246,       1073746075, 4255,       1073746081, 4346,
    1073746172, 4351,       1073746181, 4397,       1073746225, 4494,
    1073746336, 4538,       1073746416, 4607,       1073746944, 8191};
static const uint16_t kID_StartTable2Size = 4;
static const int32_t kID_StartTable2[4] = {1073741824, 3509, 1073745408, 8191};
static const uint16_t kID_StartTable3Size = 2;
static const int32_t kID_StartTable3[2] = {1073741824, 8191};
static const uint16_t kID_StartTable4Size = 2;
static const int32_t kID_StartTable4[2] = {1073741824, 8140};
static const uint16_t kID_StartTable5Size = 100;
static const int32_t kID_StartTable5[100] = {
    1073741824, 1164,       1073743056, 1277,       1073743104, 1548,
    1073743376, 1567,       1073743402, 1579,       1073743424, 1646,
    1073743487, 1693,       1073743520, 1775,       1073743639, 1823,
    1073743650, 1928,       1073743755, 1934,       1073743760, 1965,
    1073743792, 1969,       1073743863, 2049,       1073743875, 2053,
    1073743879, 2058,       1073743884, 2082,       1073743936, 2163,
    1073744002, 2227,       1073744114, 2295,       2299,       1073744138,
    2341,       1073744176, 2374,       1073744224, 2428,       1073744260,
    2482,       2511,       1073744352, 2532,       1073744358, 2543,
    1073744378, 2558,       1073744384, 2600,       1073744448, 2626,
    1073744452, 2635,       1073744480, 2678,       2682,       1073744510,
    2735,       2737,       1073744565, 2742,       1073744569, 2749,
    2752,       2754,       1073744603, 2781,       1073744608, 2794,
    1073744626, 2804,       1073744641, 2822,       1073744649, 2830,
    1073744657, 2838,       1073744672, 2854,       1073744680, 2862,
    1073744688, 2906,       1073744732, 2911,       1073744740, 2917,
    1073744832, 3042,       1073744896, 8191};
static const uint16_t kID_StartTable6Size = 6;
static const int32_t kID_StartTable6[6] = {1073741824, 6051,       1073747888,
                                           6086,       1073747915, 6139};
static const uint16_t kID_StartTable7Size = 48;
static const int32_t kID_StartTable7[48] = {
    1073748224, 6765,       1073748592, 6873,       1073748736, 6918,
    1073748755, 6935,       6941,       1073748767, 6952,       1073748778,
    6966,       1073748792, 6972,       6974,       1073748800, 6977,
    1073748803, 6980,       1073748806, 7089,       1073748947, 7485,
    1073749328, 7567,       1073749394, 7623,       1073749488, 7675,
    1073749616, 7796,       1073749622, 7932,       1073749793, 7994,
    1073749825, 8026,       1073749862, 8126,       1073749954, 8135,
    1073749962, 8143,       1073749970, 8151,       1073749978, 8156};
bool ID_Start::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kID_StartTable0, kID_StartTable0Size, c);
    case 1:
      return LookupPredicate(kID_StartTable1, kID_StartTable1Size, c);
    case 2:
      return LookupPredicate(kID_StartTable2, kID_StartTable2Size, c);
    case 3:
      return LookupPredicate(kID_StartTable3, kID_StartTable3Size, c);
    case 4:
      return LookupPredicate(kID_StartTable4, kID_StartTable4Size, c);
    case 5:
      return LookupPredicate(kID_StartTable5, kID_StartTable5Size, c);
    case 6:
      return LookupPredicate(kID_StartTable6, kID_StartTable6Size, c);
    case 7:
      return LookupPredicate(kID_StartTable7, kID_StartTable7Size, c);
    default:
      return false;
  }
}

// ID_Continue:          point.category in ['Nd', 'Mn', 'Mc', 'Pc'] or
// 'Other_ID_Continue' in point.properties or 'JS_ID_Continue' in
// point.properties

static const uint16_t kID_ContinueTable0Size = 315;
static const int32_t kID_ContinueTable0[315] = {
    1073741872, 57,         95,         183,        1073742592, 879,
    903,        1073742979, 1159,       1073743249, 1469,       1471,
    1073743297, 1474,       1073743300, 1477,       1479,       1073743376,
    1562,       1073743435, 1641,       1648,       1073743574, 1756,
    1073743583, 1764,       1073743591, 1768,       1073743594, 1773,
    1073743600, 1785,       1809,       1073743664, 1866,       1073743782,
    1968,       1073743808, 1993,       1073743851, 2035,       1073743894,
    2073,       1073743899, 2083,       1073743909, 2087,       1073743913,
    2093,       1073743961, 2139,       1073744100, 2307,       1073744186,
    2364,       1073744190, 2383,       1073744209, 2391,       1073744226,
    2403,       1073744230, 2415,       1073744257, 2435,       2492,
    1073744318, 2500,       1073744327, 2504,       1073744331, 2509,
    2519,       1073744354, 2531,       1073744358, 2543,       1073744385,
    2563,       2620,       1073744446, 2626,       1073744455, 2632,
    1073744459, 2637,       2641,       1073744486, 2673,       2677,
    1073744513, 2691,       2748,       1073744574, 2757,       1073744583,
    2761,       1073744587, 2765,       1073744610, 2787,       1073744614,
    2799,       1073744641, 2819,       2876,       1073744702, 2884,
    1073744711, 2888,       1073744715, 2893,       1073744726, 2903,
    1073744738, 2915,       1073744742, 2927,       2946,       1073744830,
    3010,       1073744838, 3016,       1073744842, 3021,       3031,
    1073744870, 3055,       1073744896, 3075,       1073744958, 3140,
    1073744966, 3144,       1073744970, 3149,       1073744981, 3158,
    1073744994, 3171,       1073744998, 3183,       1073745025, 3203,
    3260,       1073745086, 3268,       1073745094, 3272,       1073745098,
    3277,       1073745109, 3286,       1073745122, 3299,       1073745126,
    3311,       1073745153, 3331,       1073745214, 3396,       1073745222,
    3400,       1073745226, 3405,       3415,       1073745250, 3427,
    1073745254, 3439,       1073745282, 3459,       3530,       1073745359,
    3540,       3542,       1073745368, 3551,       1073745382, 3567,
    1073745394, 3571,       3633,       1073745460, 3642,       1073745479,
    3662,       1073745488, 3673,       3761,       1073745588, 3769,
    1073745595, 3772,       1073745608, 3789,       1073745616, 3801,
    1073745688, 3865,       1073745696, 3881,       3893,       3895,
    3897,       1073745726, 3903,       1073745777, 3972,       1073745798,
    3975,       1073745805, 3991,       1073745817, 4028,       4038,
    1073745963, 4158,       1073745984, 4169,       1073746006, 4185,
    1073746014, 4192,       1073746018, 4196,       1073746023, 4205,
    1073746033, 4212,       1073746050, 4237,       1073746063, 4253,
    1073746781, 4959,       1073746793, 4977,       1073747730, 5908,
    1073747762, 5940,       1073747794, 5971,       1073747826, 6003,
    1073747892, 6099,       6109,       1073747936, 6121,       1073747979,
    6157,       1073747984, 6169,       6313,       1073748256, 6443,
    1073748272, 6459,       1073748294, 6479,       1073748400, 6592,
    1073748424, 6601,       1073748432, 6618,       1073748503, 6683,
    1073748565, 6750,       1073748576, 6780,       1073748607, 6793,
    1073748624, 6809,       1073748656, 6845,       1073748736, 6916,
    1073748788, 6980,       1073748816, 7001,       1073748843, 7027,
    1073748864, 7042,       1073748897, 7085,       1073748912, 7097,
    1073748966, 7155,       1073749028, 7223,       1073749056, 7241,
    1073749072, 7257,       1073749200, 7378,       1073749204, 7400,
    7405,       1073749234, 7412,       1073749240, 7417,       1073749440,
    7669,       1073749500, 7679};
static const uint16_t kID_ContinueTable1Size = 19;
static const int32_t kID_ContinueTable1[19] = {
    1073741836, 13,   1073741887, 64,         84,
    1073742032, 220,  225,        1073742053, 240,
    1073745135, 3313, 3455,       1073745376, 3583,
    1073745962, 4143, 1073746073, 4250};
static const uint16_t kID_ContinueTable5Size = 63;
static const int32_t kID_ContinueTable5[63] = {
    1073743392, 1577,       1647,       1073743476, 1661,       1695,
    1073743600, 1777,       2050,       2054,       2059,       1073743907,
    2087,       1073744000, 2177,       1073744052, 2244,       1073744080,
    2265,       1073744096, 2289,       1073744128, 2313,       1073744166,
    2349,       1073744199, 2387,       1073744256, 2435,       1073744307,
    2496,       1073744336, 2521,       2533,       1073744368, 2553,
    1073744425, 2614,       2627,       1073744460, 2637,       1073744464,
    2649,       1073744507, 2685,       2736,       1073744562, 2740,
    1073744567, 2744,       1073744574, 2751,       2753,       1073744619,
    2799,       1073744629, 2806,       1073744867, 3050,       1073744876,
    3053,       1073744880, 3065};
static const uint16_t kID_ContinueTable7Size = 12;
static const int32_t kID_ContinueTable7[12] = {
    6942, 1073749504, 7695, 1073749536, 7725, 1073749555,
    7732, 1073749581, 7759, 1073749776, 7961, 7999};
bool ID_Continue::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kID_ContinueTable0, kID_ContinueTable0Size, c);
    case 1:
      return LookupPredicate(kID_ContinueTable1, kID_ContinueTable1Size, c);
    case 5:
      return LookupPredicate(kID_ContinueTable5, kID_ContinueTable5Size, c);
    case 7:
      return LookupPredicate(kID_ContinueTable7, kID_ContinueTable7Size, c);
    default:
      return false;
  }
}

// WhiteSpace:           (point.category == 'Zs') or ('JS_White_Space' in
// point.properties)

static const uint16_t kWhiteSpaceTable0Size = 6;
static const int32_t kWhiteSpaceTable0[6] = {9, 1073741835, 12, 32, 160, 5760};
static const uint16_t kWhiteSpaceTable1Size = 5;
static const int32_t kWhiteSpaceTable1[5] = {1073741824, 10, 47, 95, 4096};
static const uint16_t kWhiteSpaceTable7Size = 1;
static const int32_t kWhiteSpaceTable7[1] = {7935};
bool WhiteSpace::Is(uchar c) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupPredicate(kWhiteSpaceTable0, kWhiteSpaceTable0Size, c);
    case 1:
      return LookupPredicate(kWhiteSpaceTable1, kWhiteSpaceTable1Size, c);
    case 7:
      return LookupPredicate(kWhiteSpaceTable7, kWhiteSpaceTable7Size, c);
    default:
      return false;
  }
}
#endif  // !V8_INTL_SUPPORT

#ifndef V8_INTL_SUPPORT
static const MultiCharacterSpecialCase<2> kToLowercaseMultiStrings0[2] = {
    {{105, 775}}, {{kSentinel}}};
static const uint16_t kToLowercaseTable0Size = 488;
static const int32_t kToLowercaseTable0[976] = {
    1073741889, 128,   90,         128,   1073742016, 128,   214,        128,
    1073742040, 128,   222,        128,   256,        4,     258,        4,
    260,        4,     262,        4,     264,        4,     266,        4,
    268,        4,     270,        4,     272,        4,     274,        4,
    276,        4,     278,        4,     280,        4,     282,        4,
    284,        4,     286,        4,     288,        4,     290,        4,
    292,        4,     294,        4,     296,        4,     298,        4,
    300,        4,     302,        4,     304,        1,     306,        4,
    308,        4,     310,        4,     313,        4,     315,        4,
    317,        4,     319,        4,     321,        4,     323,        4,
    325,        4,     327,        4,     330,        4,     332,        4,
    334,        4,     336,        4,     338,        4,     340,        4,
    342,        4,     344,        4,     346,        4,     348,        4,
    350,        4,     352,        4,     354,        4,     356,        4,
    358,        4,     360,        4,     362,        4,     364,        4,
    366,        4,     368,        4,     370,        4,     372,        4,
    374,        4,     376,        -484,  377,        4,     379,        4,
    381,        4,     385,        840,   386,        4,     388,        4,
    390,        824,   391,        4,     1073742217, 820,   394,        820,
    395,        4,     398,        316,   399,        808,   400,        812,
    401,        4,     403,        820,   404,        828,   406,        844,
    407,        836,   408,        4,     412,        844,   413,        852,
    415,        856,   416,        4,     418,        4,     420,        4,
    422,        872,   423,        4,     425,        872,   428,        4,
    430,        872,   431,        4,     1073742257, 868,   434,        868,
    435,        4,     437,        4,     439,        876,   440,        4,
    444,        4,     452,        8,     453,        4,     455,        8,
    456,        4,     458,        8,     459,        4,     461,        4,
    463,        4,     465,        4,     467,        4,     469,        4,
    471,        4,     473,        4,     475,        4,     478,        4,
    480,        4,     482,        4,     484,        4,     486,        4,
    488,        4,     490,        4,     492,        4,     494,        4,
    497,        8,     498,        4,     500,        4,     502,        -388,
    503,        -224,  504,        4,     506,        4,     508,        4,
    510,        4,     512,        4,     514,        4,     516,        4,
    518,        4,     520,        4,     522,        4,     524,        4,
    526,        4,     528,        4,     530,        4,     532,        4,
    534,        4,     536,        4,     538,        4,     540,        4,
    542,        4,     544,        -520,  546,        4,     548,        4,
    550,        4,     552,        4,     554,        4,     556,        4,
    558,        4,     560,        4,     562,        4,     570,        43180,
    571,        4,     573,        -652,  574,        43168, 577,        4,
    579,        -780,  580,        276,   581,        284,   582,        4,
    584,        4,     586,        4,     588,        4,     590,        4,
    880,        4,     882,        4,     886,        4,     895,        464,
    902,        152,   1073742728, 148,   906,        148,   908,        256,
    1073742734, 252,   911,        252,   1073742737, 128,   929,        128,
    931,        6,     1073742756, 128,   939,        128,   975,        32,
    984,        4,     986,        4,     988,        4,     990,        4,
    992,        4,     994,        4,     996,        4,     998,        4,
    1000,       4,     1002,       4,     1004,       4,     1006,       4,
    1012,       -240,  1015,       4,     1017,       -28,   1018,       4,
    1073742845, -520,  1023,       -520,  1073742848, 320,   1039,       320,
    1073742864, 128,   1071,       128,   1120,       4,     1122,       4,
    1124,       4,     1126,       4,     1128,       4,     1130,       4,
    1132,       4,     1134,       4,     1136,       4,     1138,       4,
    1140,       4,     1142,       4,     1144,       4,     1146,       4,
    1148,       4,     1150,       4,     1152,       4,     1162,       4,
    1164,       4,     1166,       4,     1168,       4,     1170,       4,
    1172,       4,     1174,       4,     1176,       4,     1178,       4,
    1180,       4,     1182,       4,     1184,       4,     1186,       4,
    1188,       4,     1190,       4,     1192,       4,     1194,       4,
    1196,       4,     1198,       4,     1200,       4,     1202,       4,
    1204,       4,     1206,       4,     1208,       4,     1210,       4,
    1212,       4,     1214,       4,     1216,       60,    1217,       4,
    1219,       4,     1221,       4,     1223,       4,     1225,       4,
    1227,       4,     1229,       4,     1232,       4,     1234,       4,
    1236,       4,     1238,       4,     1240,       4,     1242,       4,
    1244,       4,     1246,       4,     1248,       4,     1250,       4,
    1252,       4,     1254,       4,     1256,       4,     1258,       4,
    1260,       4,     1262,       4,     1264,       4,     1266,       4,
    1268,       4,     1270,       4,     1272,       4,     1274,       4,
    1276,       4,     1278,       4,     1280,       4,     1282,       4,
    1284,       4,     1286,       4,     1288,       4,     1290,       4,
    1292,       4,     1294,       4,     1296,       4,     1298,       4,
    1300,       4,     1302,       4,     1304,       4,     1306,       4,
    1308,       4,     1310,       4,     1312,       4,     1314,       4,
    1316,       4,     1318,       4,     1320,       4,     1322,       4,
    1324,       4,     1326,       4,     1073743153, 192,   1366,       192,
    1073746080, 29056, 4293,       29056, 4295,       29056, 4301,       29056,
    7680,       4,     7682,       4,     7684,       4,     7686,       4,
    7688,       4,     7690,       4,     7692,       4,     7694,       4,
    7696,       4,     7698,       4,     7700,       4,     7702,       4,
    7704,       4,     7706,       4,     7708,       4,     7710,       4,
    7712,       4,     7714,       4,     7716,       4,     7718,       4,
    7720,       4,     7722,       4,     7724,       4,     7726,       4,
    7728,       4,     7730,       4,     7732,       4,     7734,       4,
    7736,       4,     7738,       4,     7740,       4,     7742,       4,
    7744,       4,     7746,       4,     7748,       4,     7750,       4,
    7752,       4,     7754,       4,     7756,       4,     7758,       4,
    7760,       4,     7762,       4,     7764,       4,     7766,       4,
    7768,       4,     7770,       4,     7772,       4,     7774,       4,
    7776,       4,     7778,       4,     7780,       4,     7782,       4,
    7784,       4,     7786,       4,     7788,       4,     7790,       4,
    7792,       4,     7794,       4,     7796,       4,     7798,       4,
    7800,       4,     7802,       4,     7804,       4,     7806,       4,
    7808,       4,     7810,       4,     7812,       4,     7814,       4,
    7816,       4,     7818,       4,     7820,       4,     7822,       4,
    7824,       4,     7826,       4,     7828,       4,     7838,       -30460,
    7840,       4,     7842,       4,     7844,       4,     7846,       4,
    7848,       4,     7850,       4,     7852,       4,     7854,       4,
    7856,       4,     7858,       4,     7860,       4,     7862,       4,
    7864,       4,     7866,       4,     7868,       4,     7870,       4,
    7872,       4,     7874,       4,     7876,       4,     7878,       4,
    7880,       4,     7882,       4,     7884,       4,     7886,       4,
    7888,       4,     7890,       4,     7892,       4,     7894,       4,
    7896,       4,     7898,       4,     7900,       4,     7902,       4,
    7904,       4,     7906,       4,     7908,       4,     7910,       4,
    7912,       4,     7914,       4,     7916,       4,     7918,       4,
    7920,       4,     7922,       4,     7924,       4,     7926,       4,
    7928,       4,     7930,       4,     7932,       4,     7934,       4,
    1073749768, -32,   7951,       -32,   1073749784, -32,   7965,       -32,
    1073749800, -32,   7983,       -32,   1073749816, -32,   7999,       -32,
    1073749832, -32,   8013,       -32,   8025,       -32,   8027,       -32,
    8029,       -32,   8031,       -32,   1073749864, -32,   8047,       -32,
    1073749896, -32,   8079,       -32,   1073749912, -32,   8095,       -32,
    1073749928, -32,   8111,       -32,   1073749944, -32,   8121,       -32,
    1073749946, -296,  8123,       -296,  8124,       -36,   1073749960, -344,
    8139,       -344,  8140,       -36,   1073749976, -32,   8153,       -32,
    1073749978, -400,  8155,       -400,  1073749992, -32,   8169,       -32,
    1073749994, -448,  8171,       -448,  8172,       -28,   1073750008, -512,
    8185,       -512,  1073750010, -504,  8187,       -504,  8188,       -36};
static const uint16_t kToLowercaseMultiStrings0Size = 2;
static const MultiCharacterSpecialCase<1> kToLowercaseMultiStrings1[1] = {
    {{kSentinel}}};
static const uint16_t kToLowercaseTable1Size = 79;
static const int32_t kToLowercaseTable1[158] = {
    294,        -30068, 298,        -33532, 299,  -33048, 306,        112,
    1073742176, 64,     367,        64,     387,  4,      1073743030, 104,
    1231,       104,    1073744896, 192,    3118, 192,    3168,       4,
    3170,       -42972, 3171,       -15256, 3172, -42908, 3175,       4,
    3177,       4,      3179,       4,      3181, -43120, 3182,       -42996,
    3183,       -43132, 3184,       -43128, 3186, 4,      3189,       4,
    1073745022, -43260, 3199,       -43260, 3200, 4,      3202,       4,
    3204,       4,      3206,       4,      3208, 4,      3210,       4,
    3212,       4,      3214,       4,      3216, 4,      3218,       4,
    3220,       4,      3222,       4,      3224, 4,      3226,       4,
    3228,       4,      3230,       4,      3232, 4,      3234,       4,
    3236,       4,      3238,       4,      3240, 4,      3242,       4,
    3244,       4,      3246,       4,      3248, 4,      3250,       4,
    3252,       4,      3254,       4,      3256, 4,      3258,       4,
    3260,       4,      3262,       4,      3264, 4,      3266,       4,
    3268,       4,      3270,       4,      3272, 4,      3274,       4,
    3276,       4,      3278,       4,      3280, 4,      3282,       4,
    3284,       4,      3286,       4,      3288, 4,      3290,       4,
    3292,       4,      3294,       4,      3296, 4,      3298,       4,
    3307,       4,      3309,       4,      3314, 4};
static const uint16_t kToLowercaseMultiStrings1Size = 1;
static const MultiCharacterSpecialCase<1> kToLowercaseMultiStrings5[1] = {
    {{kSentinel}}};
static const uint16_t kToLowercaseTable5Size = 103;
static const int32_t kToLowercaseTable5[206] = {
    1600, 4,       1602, 4,       1604, 4,       1606, 4,       1608, 4,
    1610, 4,       1612, 4,       1614, 4,       1616, 4,       1618, 4,
    1620, 4,       1622, 4,       1624, 4,       1626, 4,       1628, 4,
    1630, 4,       1632, 4,       1634, 4,       1636, 4,       1638, 4,
    1640, 4,       1642, 4,       1644, 4,       1664, 4,       1666, 4,
    1668, 4,       1670, 4,       1672, 4,       1674, 4,       1676, 4,
    1678, 4,       1680, 4,       1682, 4,       1684, 4,       1686, 4,
    1688, 4,       1690, 4,       1826, 4,       1828, 4,       1830, 4,
    1832, 4,       1834, 4,       1836, 4,       1838, 4,       1842, 4,
    1844, 4,       1846, 4,       1848, 4,       1850, 4,       1852, 4,
    1854, 4,       1856, 4,       1858, 4,       1860, 4,       1862, 4,
    1864, 4,       1866, 4,       1868, 4,       1870, 4,       1872, 4,
    1874, 4,       1876, 4,       1878, 4,       1880, 4,       1882, 4,
    1884, 4,       1886, 4,       1888, 4,       1890, 4,       1892, 4,
    1894, 4,       1896, 4,       1898, 4,       1900, 4,       1902, 4,
    1913, 4,       1915, 4,       1917, -141328, 1918, 4,       1920, 4,
    1922, 4,       1924, 4,       1926, 4,       1931, 4,       1933, -169120,
    1936, 4,       1938, 4,       1942, 4,       1944, 4,       1946, 4,
    1948, 4,       1950, 4,       1952, 4,       1954, 4,       1956, 4,
    1958, 4,       1960, 4,       1962, -169232, 1963, -169276, 1964, -169260,
    1965, -169220, 1968, -169032, 1969, -169128};
static const uint16_t kToLowercaseMultiStrings5Size = 1;
static const MultiCharacterSpecialCase<1> kToLowercaseMultiStrings7[1] = {
    {{kSentinel}}};
static const uint16_t kToLowercaseTable7Size = 2;
static const int32_t kToLowercaseTable7[4] = {1073749793, 128, 7994, 128};
static const uint16_t kToLowercaseMultiStrings7Size = 1;
int ToLowercase::Convert(uchar c, uchar n, uchar* result,
                         bool* allow_caching_ptr) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupMapping<true>(kToLowercaseTable0, kToLowercaseTable0Size,
                                 kToLowercaseMultiStrings0, c, n, result,
                                 allow_caching_ptr);
    case 1:
      return LookupMapping<true>(kToLowercaseTable1, kToLowercaseTable1Size,
                                 kToLowercaseMultiStrings1, c, n, result,
                                 allow_caching_ptr);
    case 5:
      return LookupMapping<true>(kToLowercaseTable5, kToLowercaseTable5Size,
                                 kToLowercaseMultiStrings5, c, n, result,
                                 allow_caching_ptr);
    case 7:
      return LookupMapping<true>(kToLowercaseTable7, kToLowercaseTable7Size,
                                 kToLowercaseMultiStrings7, c, n, result,
                                 allow_caching_ptr);
    default:
      return 0;
  }
}

static const MultiCharacterSpecialCase<3> kToUppercaseMultiStrings0[62] = {
    {{83, 83, kSentinel}},    {{700, 78, kSentinel}},
    {{74, 780, kSentinel}},   {{921, 776, 769}},
    {{933, 776, 769}},        {{1333, 1362, kSentinel}},
    {{72, 817, kSentinel}},   {{84, 776, kSentinel}},
    {{87, 778, kSentinel}},   {{89, 778, kSentinel}},
    {{65, 702, kSentinel}},   {{933, 787, kSentinel}},
    {{933, 787, 768}},        {{933, 787, 769}},
    {{933, 787, 834}},        {{7944, 921, kSentinel}},
    {{7945, 921, kSentinel}}, {{7946, 921, kSentinel}},
    {{7947, 921, kSentinel}}, {{7948, 921, kSentinel}},
    {{7949, 921, kSentinel}}, {{7950, 921, kSentinel}},
    {{7951, 921, kSentinel}}, {{7976, 921, kSentinel}},
    {{7977, 921, kSentinel}}, {{7978, 921, kSentinel}},
    {{7979, 921, kSentinel}}, {{7980, 921, kSentinel}},
    {{7981, 921, kSentinel}}, {{7982, 921, kSentinel}},
    {{7983, 921, kSentinel}}, {{8040, 921, kSentinel}},
    {{8041, 921, kSentinel}}, {{8042, 921, kSentinel}},
    {{8043, 921, kSentinel}}, {{8044, 921, kSentinel}},
    {{8045, 921, kSentinel}}, {{8046, 921, kSentinel}},
    {{8047, 921, kSentinel}}, {{8122, 921, kSentinel}},
    {{913, 921, kSentinel}},  {{902, 921, kSentinel}},
    {{913, 834, kSentinel}},  {{913, 834, 921}},
    {{8138, 921, kSentinel}}, {{919, 921, kSentinel}},
    {{905, 921, kSentinel}},  {{919, 834, kSentinel}},
    {{919, 834, 921}},        {{921, 776, 768}},
    {{921, 834, kSentinel}},  {{921, 776, 834}},
    {{933, 776, 768}},        {{929, 787, kSentinel}},
    {{933, 834, kSentinel}},  {{933, 776, 834}},
    {{8186, 921, kSentinel}}, {{937, 921, kSentinel}},
    {{911, 921, kSentinel}},  {{937, 834, kSentinel}},
    {{937, 834, 921}},        {{kSentinel}}};
static const uint16_t kToUppercaseTable0Size = 590;
static const int32_t kToUppercaseTable0[1180] = {
    1073741921, -128,   122,        -128,   181,        2972,
    223,        1,      1073742048, -128,   246,        -128,
    1073742072, -128,   254,        -128,   255,        484,
    257,        -4,     259,        -4,     261,        -4,
    263,        -4,     265,        -4,     267,        -4,
    269,        -4,     271,        -4,     273,        -4,
    275,        -4,     277,        -4,     279,        -4,
    281,        -4,     283,        -4,     285,        -4,
    287,        -4,     289,        -4,     291,        -4,
    293,        -4,     295,        -4,     297,        -4,
    299,        -4,     301,        -4,     303,        -4,
    305,        -928,   307,        -4,     309,        -4,
    311,        -4,     314,        -4,     316,        -4,
    318,        -4,     320,        -4,     322,        -4,
    324,        -4,     326,        -4,     328,        -4,
    329,        5,      331,        -4,     333,        -4,
    335,        -4,     337,        -4,     339,        -4,
    341,        -4,     343,        -4,     345,        -4,
    347,        -4,     349,        -4,     351,        -4,
    353,        -4,     355,        -4,     357,        -4,
    359,        -4,     361,        -4,     363,        -4,
    365,        -4,     367,        -4,     369,        -4,
    371,        -4,     373,        -4,     375,        -4,
    378,        -4,     380,        -4,     382,        -4,
    383,        -1200,  384,        780,    387,        -4,
    389,        -4,     392,        -4,     396,        -4,
    402,        -4,     405,        388,    409,        -4,
    410,        652,    414,        520,    417,        -4,
    419,        -4,     421,        -4,     424,        -4,
    429,        -4,     432,        -4,     436,        -4,
    438,        -4,     441,        -4,     445,        -4,
    447,        224,    453,        -4,     454,        -8,
    456,        -4,     457,        -8,     459,        -4,
    460,        -8,     462,        -4,     464,        -4,
    466,        -4,     468,        -4,     470,        -4,
    472,        -4,     474,        -4,     476,        -4,
    477,        -316,   479,        -4,     481,        -4,
    483,        -4,     485,        -4,     487,        -4,
    489,        -4,     491,        -4,     493,        -4,
    495,        -4,     496,        9,      498,        -4,
    499,        -8,     501,        -4,     505,        -4,
    507,        -4,     509,        -4,     511,        -4,
    513,        -4,     515,        -4,     517,        -4,
    519,        -4,     521,        -4,     523,        -4,
    525,        -4,     527,        -4,     529,        -4,
    531,        -4,     533,        -4,     535,        -4,
    537,        -4,     539,        -4,     541,        -4,
    543,        -4,     547,        -4,     549,        -4,
    551,        -4,     553,        -4,     555,        -4,
    557,        -4,     559,        -4,     561,        -4,
    563,        -4,     572,        -4,     1073742399, 43260,
    576,        43260,  578,        -4,     583,        -4,
    585,        -4,     587,        -4,     589,        -4,
    591,        -4,     592,        43132,  593,        43120,
    594,        43128,  595,        -840,   596,        -824,
    1073742422, -820,   599,        -820,   601,        -808,
    603,        -812,   604,        169276, 608,        -820,
    609,        169260, 611,        -828,   613,        169120,
    614,        169232,
"""


```