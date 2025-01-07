Response:
My thinking process to analyze the provided C++ code snippet and fulfill the user's request goes through these stages:

1. **Identify the Core Functionality:** The code consists primarily of large, static constant arrays (`kToUppercaseTable...`, `kEcma262CanonicalizeTable...`, `kEcma262UnCanonicalizeMultiStrings...`, etc.) and a few `Convert` functions. The naming of the tables and functions strongly suggests character case conversion and Unicode normalization. Keywords like "Uppercase", "Canonicalize", and "UnCanonicalize" are key.

2. **Determine Data Structure:**  The tables are arrays of `int32_t` and `uint16_t`. The multi-string arrays are arrays of structs (`MultiCharacterSpecialCase`). The `Convert` functions take a `uchar` (likely an unsigned char representing a Unicode code point), another `uchar`, and a pointer to a `uchar` for the result. This suggests a mapping from one or two input characters to one or more output characters.

3. **Infer the Purpose of Tables and Functions:**
    * `kToUppercase...`:  Likely involved in converting characters to their uppercase equivalents.
    * `kEcma262Canonicalize...`:  Suggests applying some form of canonicalization as defined by the ECMAScript specification. This often involves normalizing different representations of the same character to a standard form.
    * `kEcma262UnCanonicalize...`:  The opposite of canonicalization. It probably maps canonical forms back to a representative uncanonical form, although the exact purpose is less immediately obvious than the other two.
    * `LookupMapping`: This is a template function used by the `Convert` methods. It strongly implies a lookup operation within the tables. The `MultiCharacterSpecialCase` suggests handling cases where the conversion depends on multiple input characters.

4. **Check for .tq Extension:** The prompt explicitly mentions checking for a `.tq` extension. Since the provided code is `.cc`, it's confirmed to be standard C++ source code, not Torque.

5. **Relate to JavaScript (if applicable):**  The prompt asks if there's a relationship to JavaScript. Given the context of V8 (the JavaScript engine for Chrome and Node.js), these functions are almost certainly used internally to implement JavaScript's string manipulation methods, particularly those related to case conversion and normalization. Specifically, `toUpperCase()` and potentially methods related to Unicode normalization (though JavaScript's normalization support has evolved).

6. **Construct JavaScript Examples:**  To illustrate the JavaScript connection, provide simple examples of `toUpperCase()` that would internally utilize the C++ functions.

7. **Code Logic Inference (with assumptions):** The `Convert` functions use a `chunk_index` based on bit shifting. This suggests a partitioning of the Unicode code space into chunks for efficient lookup. The `LookupMapping` function (though not fully shown) probably performs a binary search or some similar optimized search within the appropriate table based on the input character.

    * **Assumption for Input/Output:** If we input a lowercase 'a' to `ToUppercase::Convert`, it should output an uppercase 'A'. Similarly, specific Unicode characters with defined uppercase mappings would follow that pattern. For canonicalization, the input and output might be different representations of the same logical character.

8. **Identify Common Programming Errors:**  Relate the functionality to potential programmer errors. Incorrect case conversion or failure to normalize strings before comparison are common issues. Provide JavaScript examples of these errors.

9. **Synthesize the Functionality Summary:**  Combine the identified functionalities into a concise summary, focusing on the core purposes of case conversion and Unicode canonicalization within the V8 engine.

10. **Address Part Numbering:** Acknowledge that this is part 3 of 6, as requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Could the numbers in the tables be direct mappings?  **Correction:** The negative numbers likely represent offsets or flags within the lookup process, indicating special handling or multi-character results. The bit shifting in `chunk_index` also points to a more structured lookup than a simple array index.
* **Focusing on Torque:** The prompt specifically asks about `.tq`. While it's not the case here, being aware of Torque (V8's internal DSL) is important for understanding other parts of V8. The code structure (tables and lookup functions) is conceptually similar to what generated Torque code might do.
* **Overly Detailed Code Explanation:**  Resist the urge to explain every single number in the tables. Focus on the high-level purpose and data structures. The exact numerical values are implementation details.
* **JavaScript Normalization Complexity:** Acknowledge that JavaScript's Unicode normalization is more complex than simple case conversion and has specific APIs (`normalize()`). The canonicalization functions in the C++ code are likely related but might not directly map to the `normalize()` method in all its variations.

By following this process, I can systematically analyze the code snippet and generate a comprehensive and accurate response to the user's request.
好的，让我们来分析一下提供的这段 `v8/src/strings/unicode.cc` 代码片段的功能。

**功能归纳**

从代码片段中的常量数组名称和 `Convert` 函数的名称来看，这段代码的主要功能是提供 **Unicode 字符的大小写转换** 和 **ECMAScript 规范化的功能**。  具体来说：

1. **大小写转换 (ToUppercase):** 提供了将 Unicode 字符转换为大写形式的功能。
2. **ECMAScript 规范化 (Ecma262Canonicalize):**  提供了将 Unicode 字符规范化为特定形式的功能，这遵循 ECMAScript 规范。
3. **ECMAScript 反规范化 (Ecma262UnCanonicalize):** 提供了将规范化的 Unicode 字符转换回非规范化形式的功能。

**详细分析**

*   **数据结构：** 代码中定义了大量的静态常量数组，如 `kToUppercaseTable0`，`kEcma262CanonicalizeTable0`，`kEcma262UnCanonicalizeMultiStrings0` 等。这些数组存储了用于进行大小写转换和规范化的映射关系。
    *   `kToUppercaseTableX`:  存储了字符到其大写形式的映射。
    *   `kEcma262CanonicalizeTableX`: 存储了字符到其规范化形式的映射。
    *   `kEcma262UnCanonicalizeMultiStringsX`: 存储了从规范化形式到非规范化形式的映射，特别是处理多个字符组成的规范化形式。
*   **`Convert` 函数：**  提供了实际的转换逻辑。它们接收一个或两个 `uchar` 类型的字符作为输入（`c` 和 `n`），并尝试将 `c` 转换为大写或规范化形式，结果存储在 `result` 指针指向的内存中。 `allow_caching_ptr` 参数可能用于控制是否允许缓存转换结果。
*   **`LookupMapping` 模板函数：**  `Convert` 函数内部调用了 `LookupMapping` 模板函数，这表明实际的查找映射关系的操作是由这个函数完成的。它根据输入的字符 `c` 在相应的 `Table` 中查找映射，并处理 `MultiStrings` 中定义的特殊情况。
*   **分块处理：**  在 `Convert` 函数中，通过 `c >> 13` 将字符 `c` 分成不同的 `chunk_index`，然后根据 `chunk_index` 选择不同的映射表进行查找。这是一种优化策略，将 Unicode 字符空间划分为多个区域，提高查找效率。

**关于 .tq 结尾**

根据您的描述，如果 `v8/src/strings/unicode.cc` 文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码。由于这里的文件名是 `.cc`，所以它是一个标准的 C++ 源文件。

**与 JavaScript 的关系**

这段 C++ 代码直接关系到 JavaScript 中字符串的大小写转换和规范化功能。JavaScript 的 `String` 对象提供了一些方法，如 `toUpperCase()` 和 `toLocaleUpperCase()`，以及与 Unicode 规范化相关的方法（虽然 V8 的规范化实现可能在其他地方，但这里的大小写转换是基础）。

**JavaScript 示例**

```javascript
const str = "你好，world!";
const upperStr = str.toUpperCase();
console.log(upperStr); // 输出：你好，WORLD!

const lowerStr = upperStr.toLowerCase();
console.log(lowerStr); // 输出：你好，world!

// 假设存在一个 JavaScript 函数对应于这里的规范化 (实际 V8 的规范化 API 可能不同)
// const normalizedStr = internalNormalize(str);
// console.log(normalizedStr);
```

当 JavaScript 引擎执行 `toUpperCase()` 方法时，V8 内部就会调用类似这段 C++ 代码中的逻辑来查找和转换字符的大小写。

**代码逻辑推理**

**假设输入：**  `c` 为小写字母 'a' 的 Unicode 码点 (97)，`n` 不相关。

**输出推断：**

1. `chunk_index = 97 >> 13 = 0`。
2. 进入 `case 0` 分支。
3. 调用 `LookupMapping<true>(kToUppercaseTable0, kToUppercaseTable0Size, kToUppercaseMultiStrings0, 97, n, result, allow_caching_ptr)`。
4. `LookupMapping` 函数会在 `kToUppercaseTable0` 中查找与 97 对应的条目。
5. 如果找到，并且映射指向一个大写形式的码点，那么 `result` 指向的内存应该存储大写字母 'A' 的 Unicode 码点 (65)。

**用户常见的编程错误**

*   **大小写不敏感的比较：**  程序员经常会犯在比较字符串时没有先统一大小写的错误，导致逻辑错误。

    ```javascript
    const input = "hello";
    const expected = "HELLO";

    // 错误的比较方式
    if (input === expected) {
      console.log("匹配"); // 不会输出
    }

    // 正确的比较方式（统一转换为大写）
    if (input.toUpperCase() === expected) {
      console.log("匹配"); // 输出：匹配
    }
    ```

*   **忽略 Unicode 字符的大小写转换规则：**  某些 Unicode 字符的大小写转换规则可能不直观，直接使用简单的 ASCII 转换逻辑会导致错误。V8 的这段代码处理了这些复杂的规则。

*   **不正确的 Unicode 规范化导致比较失败：**  即使字符串在视觉上相同，但由于内部 Unicode 表示形式不同，直接比较可能会失败。在需要比较用户输入或来自不同来源的字符串时，进行规范化非常重要。虽然这段代码片段主要是大小写转换，但 `Ecma262Canonicalize` 的存在也暗示了规范化的重要性。

**归纳一下它的功能（第 3 部分）**

这段代码是 V8 引擎中处理 Unicode 字符大小写转换和 ECMAScript 规范化的核心部分。它通过预定义的静态查找表和相应的查找函数，高效地实现了将字符转换为大写以及进行规范化和反规范化的操作。这些功能是 JavaScript 字符串处理的基础，确保了 JavaScript 能够正确地处理各种 Unicode 字符的大小写和规范化需求。

Prompt: 
```
这是目录为v8/src/strings/unicode.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/strings/unicode.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
 616,        -836,   617,        -844,
    619,        42972,  620,        169220, 623,        -844,
    625,        42996,  626,        -852,   629,        -856,
    637,        42908,  640,        -872,   643,        -872,
    647,        169128, 648,        -872,   649,        -276,
    1073742474, -868,   651,        -868,   652,        -284,
    658,        -876,   670,        169032, 837,        336,
    881,        -4,     883,        -4,     887,        -4,
    1073742715, 520,    893,        520,    912,        13,
    940,        -152,   1073742765, -148,   943,        -148,
    944,        17,     1073742769, -128,   961,        -128,
    962,        -124,   1073742787, -128,   971,        -128,
    972,        -256,   1073742797, -252,   974,        -252,
    976,        -248,   977,        -228,   981,        -188,
    982,        -216,   983,        -32,    985,        -4,
    987,        -4,     989,        -4,     991,        -4,
    993,        -4,     995,        -4,     997,        -4,
    999,        -4,     1001,       -4,     1003,       -4,
    1005,       -4,     1007,       -4,     1008,       -344,
    1009,       -320,   1010,       28,     1011,       -464,
    1013,       -384,   1016,       -4,     1019,       -4,
    1073742896, -128,   1103,       -128,   1073742928, -320,
    1119,       -320,   1121,       -4,     1123,       -4,
    1125,       -4,     1127,       -4,     1129,       -4,
    1131,       -4,     1133,       -4,     1135,       -4,
    1137,       -4,     1139,       -4,     1141,       -4,
    1143,       -4,     1145,       -4,     1147,       -4,
    1149,       -4,     1151,       -4,     1153,       -4,
    1163,       -4,     1165,       -4,     1167,       -4,
    1169,       -4,     1171,       -4,     1173,       -4,
    1175,       -4,     1177,       -4,     1179,       -4,
    1181,       -4,     1183,       -4,     1185,       -4,
    1187,       -4,     1189,       -4,     1191,       -4,
    1193,       -4,     1195,       -4,     1197,       -4,
    1199,       -4,     1201,       -4,     1203,       -4,
    1205,       -4,     1207,       -4,     1209,       -4,
    1211,       -4,     1213,       -4,     1215,       -4,
    1218,       -4,     1220,       -4,     1222,       -4,
    1224,       -4,     1226,       -4,     1228,       -4,
    1230,       -4,     1231,       -60,    1233,       -4,
    1235,       -4,     1237,       -4,     1239,       -4,
    1241,       -4,     1243,       -4,     1245,       -4,
    1247,       -4,     1249,       -4,     1251,       -4,
    1253,       -4,     1255,       -4,     1257,       -4,
    1259,       -4,     1261,       -4,     1263,       -4,
    1265,       -4,     1267,       -4,     1269,       -4,
    1271,       -4,     1273,       -4,     1275,       -4,
    1277,       -4,     1279,       -4,     1281,       -4,
    1283,       -4,     1285,       -4,     1287,       -4,
    1289,       -4,     1291,       -4,     1293,       -4,
    1295,       -4,     1297,       -4,     1299,       -4,
    1301,       -4,     1303,       -4,     1305,       -4,
    1307,       -4,     1309,       -4,     1311,       -4,
    1313,       -4,     1315,       -4,     1317,       -4,
    1319,       -4,     1321,       -4,     1323,       -4,
    1325,       -4,     1327,       -4,     1073743201, -192,
    1414,       -192,   1415,       21,     7545,       141328,
    7549,       15256,  7681,       -4,     7683,       -4,
    7685,       -4,     7687,       -4,     7689,       -4,
    7691,       -4,     7693,       -4,     7695,       -4,
    7697,       -4,     7699,       -4,     7701,       -4,
    7703,       -4,     7705,       -4,     7707,       -4,
    7709,       -4,     7711,       -4,     7713,       -4,
    7715,       -4,     7717,       -4,     7719,       -4,
    7721,       -4,     7723,       -4,     7725,       -4,
    7727,       -4,     7729,       -4,     7731,       -4,
    7733,       -4,     7735,       -4,     7737,       -4,
    7739,       -4,     7741,       -4,     7743,       -4,
    7745,       -4,     7747,       -4,     7749,       -4,
    7751,       -4,     7753,       -4,     7755,       -4,
    7757,       -4,     7759,       -4,     7761,       -4,
    7763,       -4,     7765,       -4,     7767,       -4,
    7769,       -4,     7771,       -4,     7773,       -4,
    7775,       -4,     7777,       -4,     7779,       -4,
    7781,       -4,     7783,       -4,     7785,       -4,
    7787,       -4,     7789,       -4,     7791,       -4,
    7793,       -4,     7795,       -4,     7797,       -4,
    7799,       -4,     7801,       -4,     7803,       -4,
    7805,       -4,     7807,       -4,     7809,       -4,
    7811,       -4,     7813,       -4,     7815,       -4,
    7817,       -4,     7819,       -4,     7821,       -4,
    7823,       -4,     7825,       -4,     7827,       -4,
    7829,       -4,     7830,       25,     7831,       29,
    7832,       33,     7833,       37,     7834,       41,
    7835,       -236,   7841,       -4,     7843,       -4,
    7845,       -4,     7847,       -4,     7849,       -4,
    7851,       -4,     7853,       -4,     7855,       -4,
    7857,       -4,     7859,       -4,     7861,       -4,
    7863,       -4,     7865,       -4,     7867,       -4,
    7869,       -4,     7871,       -4,     7873,       -4,
    7875,       -4,     7877,       -4,     7879,       -4,
    7881,       -4,     7883,       -4,     7885,       -4,
    7887,       -4,     7889,       -4,     7891,       -4,
    7893,       -4,     7895,       -4,     7897,       -4,
    7899,       -4,     7901,       -4,     7903,       -4,
    7905,       -4,     7907,       -4,     7909,       -4,
    7911,       -4,     7913,       -4,     7915,       -4,
    7917,       -4,     7919,       -4,     7921,       -4,
    7923,       -4,     7925,       -4,     7927,       -4,
    7929,       -4,     7931,       -4,     7933,       -4,
    7935,       -4,     1073749760, 32,     7943,       32,
    1073749776, 32,     7957,       32,     1073749792, 32,
    7975,       32,     1073749808, 32,     7991,       32,
    1073749824, 32,     8005,       32,     8016,       45,
    8017,       32,     8018,       49,     8019,       32,
    8020,       53,     8021,       32,     8022,       57,
    8023,       32,     1073749856, 32,     8039,       32,
    1073749872, 296,    8049,       296,    1073749874, 344,
    8053,       344,    1073749878, 400,    8055,       400,
    1073749880, 512,    8057,       512,    1073749882, 448,
    8059,       448,    1073749884, 504,    8061,       504,
    8064,       61,     8065,       65,     8066,       69,
    8067,       73,     8068,       77,     8069,       81,
    8070,       85,     8071,       89,     8072,       61,
    8073,       65,     8074,       69,     8075,       73,
    8076,       77,     8077,       81,     8078,       85,
    8079,       89,     8080,       93,     8081,       97,
    8082,       101,    8083,       105,    8084,       109,
    8085,       113,    8086,       117,    8087,       121,
    8088,       93,     8089,       97,     8090,       101,
    8091,       105,    8092,       109,    8093,       113,
    8094,       117,    8095,       121,    8096,       125,
    8097,       129,    8098,       133,    8099,       137,
    8100,       141,    8101,       145,    8102,       149,
    8103,       153,    8104,       125,    8105,       129,
    8106,       133,    8107,       137,    8108,       141,
    8109,       145,    8110,       149,    8111,       153,
    1073749936, 32,     8113,       32,     8114,       157,
    8115,       161,    8116,       165,    8118,       169,
    8119,       173,    8124,       161,    8126,       -28820,
    8130,       177,    8131,       181,    8132,       185,
    8134,       189,    8135,       193,    8140,       181,
    1073749968, 32,     8145,       32,     8146,       197,
    8147,       13,     8150,       201,    8151,       205,
    1073749984, 32,     8161,       32,     8162,       209,
    8163,       17,     8164,       213,    8165,       28,
    8166,       217,    8167,       221,    8178,       225,
    8179,       229,    8180,       233,    8182,       237,
    8183,       241,    8188,       229};
static const uint16_t kToUppercaseMultiStrings0Size = 62;
static const MultiCharacterSpecialCase<1> kToUppercaseMultiStrings1[1] = {
    {{kSentinel}}};
static const uint16_t kToUppercaseTable1Size = 73;
static const int32_t kToUppercaseTable1[146] = {
    334,  -112,   1073742192, -64,    383,  -64,   388,  -4, 1073743056, -104,
    1257, -104,   1073744944, -192,   3166, -192,  3169, -4, 3173,       -43180,
    3174, -43168, 3176,       -4,     3178, -4,    3180, -4, 3187,       -4,
    3190, -4,     3201,       -4,     3203, -4,    3205, -4, 3207,       -4,
    3209, -4,     3211,       -4,     3213, -4,    3215, -4, 3217,       -4,
    3219, -4,     3221,       -4,     3223, -4,    3225, -4, 3227,       -4,
    3229, -4,     3231,       -4,     3233, -4,    3235, -4, 3237,       -4,
    3239, -4,     3241,       -4,     3243, -4,    3245, -4, 3247,       -4,
    3249, -4,     3251,       -4,     3253, -4,    3255, -4, 3257,       -4,
    3259, -4,     3261,       -4,     3263, -4,    3265, -4, 3267,       -4,
    3269, -4,     3271,       -4,     3273, -4,    3275, -4, 3277,       -4,
    3279, -4,     3281,       -4,     3283, -4,    3285, -4, 3287,       -4,
    3289, -4,     3291,       -4,     3293, -4,    3295, -4, 3297,       -4,
    3299, -4,     3308,       -4,     3310, -4,    3315, -4, 1073745152, -29056,
    3365, -29056, 3367,       -29056, 3373, -29056};
static const uint16_t kToUppercaseMultiStrings1Size = 1;
static const MultiCharacterSpecialCase<1> kToUppercaseMultiStrings5[1] = {
    {{kSentinel}}};
static const uint16_t kToUppercaseTable5Size = 95;
static const int32_t kToUppercaseTable5[190] = {
    1601, -4, 1603, -4, 1605, -4, 1607, -4, 1609, -4, 1611, -4, 1613, -4,
    1615, -4, 1617, -4, 1619, -4, 1621, -4, 1623, -4, 1625, -4, 1627, -4,
    1629, -4, 1631, -4, 1633, -4, 1635, -4, 1637, -4, 1639, -4, 1641, -4,
    1643, -4, 1645, -4, 1665, -4, 1667, -4, 1669, -4, 1671, -4, 1673, -4,
    1675, -4, 1677, -4, 1679, -4, 1681, -4, 1683, -4, 1685, -4, 1687, -4,
    1689, -4, 1691, -4, 1827, -4, 1829, -4, 1831, -4, 1833, -4, 1835, -4,
    1837, -4, 1839, -4, 1843, -4, 1845, -4, 1847, -4, 1849, -4, 1851, -4,
    1853, -4, 1855, -4, 1857, -4, 1859, -4, 1861, -4, 1863, -4, 1865, -4,
    1867, -4, 1869, -4, 1871, -4, 1873, -4, 1875, -4, 1877, -4, 1879, -4,
    1881, -4, 1883, -4, 1885, -4, 1887, -4, 1889, -4, 1891, -4, 1893, -4,
    1895, -4, 1897, -4, 1899, -4, 1901, -4, 1903, -4, 1914, -4, 1916, -4,
    1919, -4, 1921, -4, 1923, -4, 1925, -4, 1927, -4, 1932, -4, 1937, -4,
    1939, -4, 1943, -4, 1945, -4, 1947, -4, 1949, -4, 1951, -4, 1953, -4,
    1955, -4, 1957, -4, 1959, -4, 1961, -4};
static const uint16_t kToUppercaseMultiStrings5Size = 1;
static const MultiCharacterSpecialCase<3> kToUppercaseMultiStrings7[12] = {
    {{70, 70, kSentinel}},
    {{70, 73, kSentinel}},
    {{70, 76, kSentinel}},
    {{70, 70, 73}},
    {{70, 70, 76}},
    {{83, 84, kSentinel}},
    {{1348, 1350, kSentinel}},
    {{1348, 1333, kSentinel}},
    {{1348, 1339, kSentinel}},
    {{1358, 1350, kSentinel}},
    {{1348, 1341, kSentinel}},
    {{kSentinel}}};
static const uint16_t kToUppercaseTable7Size = 14;
static const int32_t kToUppercaseTable7[28] = {
    6912, 1,  6913, 5,  6914,       9,    6915, 13,  6916, 17,
    6917, 21, 6918, 21, 6931,       25,   6932, 29,  6933, 33,
    6934, 37, 6935, 41, 1073749825, -128, 8026, -128};
static const uint16_t kToUppercaseMultiStrings7Size = 12;
int ToUppercase::Convert(uchar c, uchar n, uchar* result,
                         bool* allow_caching_ptr) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupMapping<true>(kToUppercaseTable0, kToUppercaseTable0Size,
                                 kToUppercaseMultiStrings0, c, n, result,
                                 allow_caching_ptr);
    case 1:
      return LookupMapping<true>(kToUppercaseTable1, kToUppercaseTable1Size,
                                 kToUppercaseMultiStrings1, c, n, result,
                                 allow_caching_ptr);
    case 5:
      return LookupMapping<true>(kToUppercaseTable5, kToUppercaseTable5Size,
                                 kToUppercaseMultiStrings5, c, n, result,
                                 allow_caching_ptr);
    case 7:
      return LookupMapping<true>(kToUppercaseTable7, kToUppercaseTable7Size,
                                 kToUppercaseMultiStrings7, c, n, result,
                                 allow_caching_ptr);
    default:
      return 0;
  }
}

static const MultiCharacterSpecialCase<1> kEcma262CanonicalizeMultiStrings0[1] =
    {{{kSentinel}}};
static const uint16_t kEcma262CanonicalizeTable0Size = 498;
static const int32_t kEcma262CanonicalizeTable0[996] = {
    1073741921, -128,   122,        -128,   181,        2972,
    1073742048, -128,   246,        -128,   1073742072, -128,
    254,        -128,   255,        484,    257,        -4,
    259,        -4,     261,        -4,     263,        -4,
    265,        -4,     267,        -4,     269,        -4,
    271,        -4,     273,        -4,     275,        -4,
    277,        -4,     279,        -4,     281,        -4,
    283,        -4,     285,        -4,     287,        -4,
    289,        -4,     291,        -4,     293,        -4,
    295,        -4,     297,        -4,     299,        -4,
    301,        -4,     303,        -4,     307,        -4,
    309,        -4,     311,        -4,     314,        -4,
    316,        -4,     318,        -4,     320,        -4,
    322,        -4,     324,        -4,     326,        -4,
    328,        -4,     331,        -4,     333,        -4,
    335,        -4,     337,        -4,     339,        -4,
    341,        -4,     343,        -4,     345,        -4,
    347,        -4,     349,        -4,     351,        -4,
    353,        -4,     355,        -4,     357,        -4,
    359,        -4,     361,        -4,     363,        -4,
    365,        -4,     367,        -4,     369,        -4,
    371,        -4,     373,        -4,     375,        -4,
    378,        -4,     380,        -4,     382,        -4,
    384,        780,    387,        -4,     389,        -4,
    392,        -4,     396,        -4,     402,        -4,
    405,        388,    409,        -4,     410,        652,
    414,        520,    417,        -4,     419,        -4,
    421,        -4,     424,        -4,     429,        -4,
    432,        -4,     436,        -4,     438,        -4,
    441,        -4,     445,        -4,     447,        224,
    453,        -4,     454,        -8,     456,        -4,
    457,        -8,     459,        -4,     460,        -8,
    462,        -4,     464,        -4,     466,        -4,
    468,        -4,     470,        -4,     472,        -4,
    474,        -4,     476,        -4,     477,        -316,
    479,        -4,     481,        -4,     483,        -4,
    485,        -4,     487,        -4,     489,        -4,
    491,        -4,     493,        -4,     495,        -4,
    498,        -4,     499,        -8,     501,        -4,
    505,        -4,     507,        -4,     509,        -4,
    511,        -4,     513,        -4,     515,        -4,
    517,        -4,     519,        -4,     521,        -4,
    523,        -4,     525,        -4,     527,        -4,
    529,        -4,     531,        -4,     533,        -4,
    535,        -4,     537,        -4,     539,        -4,
    541,        -4,     543,        -4,     547,        -4,
    549,        -4,     551,        -4,     553,        -4,
    555,        -4,     557,        -4,     559,        -4,
    561,        -4,     563,        -4,     572,        -4,
    1073742399, 43260,  576,        43260,  578,        -4,
    583,        -4,     585,        -4,     587,        -4,
    589,        -4,     591,        -4,     592,        43132,
    593,        43120,  594,        43128,  595,        -840,
    596,        -824,   1073742422, -820,   599,        -820,
    601,        -808,   603,        -812,   604,        169276,
    608,        -820,   609,        169260, 611,        -828,
    613,        169120, 614,        169232, 616,        -836,
    617,        -844,   619,        42972,  620,        169220,
    623,        -844,   625,        42996,  626,        -852,
    629,        -856,   637,        42908,  640,        -872,
    643,        -872,   647,        169128, 648,        -872,
    649,        -276,   1073742474, -868,   651,        -868,
    652,        -284,   658,        -876,   670,        169032,
    837,        336,    881,        -4,     883,        -4,
    887,        -4,     1073742715, 520,    893,        520,
    940,        -152,   1073742765, -148,   943,        -148,
    1073742769, -128,   961,        -128,   962,        -124,
    1073742787, -128,   971,        -128,   972,        -256,
    1073742797, -252,   974,        -252,   976,        -248,
    977,        -228,   981,        -188,   982,        -216,
    983,        -32,    985,        -4,     987,        -4,
    989,        -4,     991,        -4,     993,        -4,
    995,        -4,     997,        -4,     999,        -4,
    1001,       -4,     1003,       -4,     1005,       -4,
    1007,       -4,     1008,       -344,   1009,       -320,
    1010,       28,     1011,       -464,   1013,       -384,
    1016,       -4,     1019,       -4,     1073742896, -128,
    1103,       -128,   1073742928, -320,   1119,       -320,
    1121,       -4,     1123,       -4,     1125,       -4,
    1127,       -4,     1129,       -4,     1131,       -4,
    1133,       -4,     1135,       -4,     1137,       -4,
    1139,       -4,     1141,       -4,     1143,       -4,
    1145,       -4,     1147,       -4,     1149,       -4,
    1151,       -4,     1153,       -4,     1163,       -4,
    1165,       -4,     1167,       -4,     1169,       -4,
    1171,       -4,     1173,       -4,     1175,       -4,
    1177,       -4,     1179,       -4,     1181,       -4,
    1183,       -4,     1185,       -4,     1187,       -4,
    1189,       -4,     1191,       -4,     1193,       -4,
    1195,       -4,     1197,       -4,     1199,       -4,
    1201,       -4,     1203,       -4,     1205,       -4,
    1207,       -4,     1209,       -4,     1211,       -4,
    1213,       -4,     1215,       -4,     1218,       -4,
    1220,       -4,     1222,       -4,     1224,       -4,
    1226,       -4,     1228,       -4,     1230,       -4,
    1231,       -60,    1233,       -4,     1235,       -4,
    1237,       -4,     1239,       -4,     1241,       -4,
    1243,       -4,     1245,       -4,     1247,       -4,
    1249,       -4,     1251,       -4,     1253,       -4,
    1255,       -4,     1257,       -4,     1259,       -4,
    1261,       -4,     1263,       -4,     1265,       -4,
    1267,       -4,     1269,       -4,     1271,       -4,
    1273,       -4,     1275,       -4,     1277,       -4,
    1279,       -4,     1281,       -4,     1283,       -4,
    1285,       -4,     1287,       -4,     1289,       -4,
    1291,       -4,     1293,       -4,     1295,       -4,
    1297,       -4,     1299,       -4,     1301,       -4,
    1303,       -4,     1305,       -4,     1307,       -4,
    1309,       -4,     1311,       -4,     1313,       -4,
    1315,       -4,     1317,       -4,     1319,       -4,
    1321,       -4,     1323,       -4,     1325,       -4,
    1327,       -4,     1073743201, -192,   1414,       -192,
    7545,       141328, 7549,       15256,  7681,       -4,
    7683,       -4,     7685,       -4,     7687,       -4,
    7689,       -4,     7691,       -4,     7693,       -4,
    7695,       -4,     7697,       -4,     7699,       -4,
    7701,       -4,     7703,       -4,     7705,       -4,
    7707,       -4,     7709,       -4,     7711,       -4,
    7713,       -4,     7715,       -4,     7717,       -4,
    7719,       -4,     7721,       -4,     7723,       -4,
    7725,       -4,     7727,       -4,     7729,       -4,
    7731,       -4,     7733,       -4,     7735,       -4,
    7737,       -4,     7739,       -4,     7741,       -4,
    7743,       -4,     7745,       -4,     7747,       -4,
    7749,       -4,     7751,       -4,     7753,       -4,
    7755,       -4,     7757,       -4,     7759,       -4,
    7761,       -4,     7763,       -4,     7765,       -4,
    7767,       -4,     7769,       -4,     7771,       -4,
    7773,       -4,     7775,       -4,     7777,       -4,
    7779,       -4,     7781,       -4,     7783,       -4,
    7785,       -4,     7787,       -4,     7789,       -4,
    7791,       -4,     7793,       -4,     7795,       -4,
    7797,       -4,     7799,       -4,     7801,       -4,
    7803,       -4,     7805,       -4,     7807,       -4,
    7809,       -4,     7811,       -4,     7813,       -4,
    7815,       -4,     7817,       -4,     7819,       -4,
    7821,       -4,     7823,       -4,     7825,       -4,
    7827,       -4,     7829,       -4,     7835,       -236,
    7841,       -4,     7843,       -4,     7845,       -4,
    7847,       -4,     7849,       -4,     7851,       -4,
    7853,       -4,     7855,       -4,     7857,       -4,
    7859,       -4,     7861,       -4,     7863,       -4,
    7865,       -4,     7867,       -4,     7869,       -4,
    7871,       -4,     7873,       -4,     7875,       -4,
    7877,       -4,     7879,       -4,     7881,       -4,
    7883,       -4,     7885,       -4,     7887,       -4,
    7889,       -4,     7891,       -4,     7893,       -4,
    7895,       -4,     7897,       -4,     7899,       -4,
    7901,       -4,     7903,       -4,     7905,       -4,
    7907,       -4,     7909,       -4,     7911,       -4,
    7913,       -4,     7915,       -4,     7917,       -4,
    7919,       -4,     7921,       -4,     7923,       -4,
    7925,       -4,     7927,       -4,     7929,       -4,
    7931,       -4,     7933,       -4,     7935,       -4,
    1073749760, 32,     7943,       32,     1073749776, 32,
    7957,       32,     1073749792, 32,     7975,       32,
    1073749808, 32,     7991,       32,     1073749824, 32,
    8005,       32,     8017,       32,     8019,       32,
    8021,       32,     8023,       32,     1073749856, 32,
    8039,       32,     1073749872, 296,    8049,       296,
    1073749874, 344,    8053,       344,    1073749878, 400,
    8055,       400,    1073749880, 512,    8057,       512,
    1073749882, 448,    8059,       448,    1073749884, 504,
    8061,       504,    1073749936, 32,     8113,       32,
    8126,       -28820, 1073749968, 32,     8145,       32,
    1073749984, 32,     8161,       32,     8165,       28};
static const uint16_t kEcma262CanonicalizeMultiStrings0Size = 1;
static const MultiCharacterSpecialCase<1> kEcma262CanonicalizeMultiStrings1[1] =
    {{{kSentinel}}};
static const uint16_t kEcma262CanonicalizeTable1Size = 73;
static const int32_t kEcma262CanonicalizeTable1[146] = {
    334,  -112,   1073742192, -64,    383,  -64,   388,  -4, 1073743056, -104,
    1257, -104,   1073744944, -192,   3166, -192,  3169, -4, 3173,       -43180,
    3174, -43168, 3176,       -4,     3178, -4,    3180, -4, 3187,       -4,
    3190, -4,     3201,       -4,     3203, -4,    3205, -4, 3207,       -4,
    3209, -4,     3211,       -4,     3213, -4,    3215, -4, 3217,       -4,
    3219, -4,     3221,       -4,     3223, -4,    3225, -4, 3227,       -4,
    3229, -4,     3231,       -4,     3233, -4,    3235, -4, 3237,       -4,
    3239, -4,     3241,       -4,     3243, -4,    3245, -4, 3247,       -4,
    3249, -4,     3251,       -4,     3253, -4,    3255, -4, 3257,       -4,
    3259, -4,     3261,       -4,     3263, -4,    3265, -4, 3267,       -4,
    3269, -4,     3271,       -4,     3273, -4,    3275, -4, 3277,       -4,
    3279, -4,     3281,       -4,     3283, -4,    3285, -4, 3287,       -4,
    3289, -4,     3291,       -4,     3293, -4,    3295, -4, 3297,       -4,
    3299, -4,     3308,       -4,     3310, -4,    3315, -4, 1073745152, -29056,
    3365, -29056, 3367,       -29056, 3373, -29056};
static const uint16_t kEcma262CanonicalizeMultiStrings1Size = 1;
static const MultiCharacterSpecialCase<1> kEcma262CanonicalizeMultiStrings5[1] =
    {{{kSentinel}}};
static const uint16_t kEcma262CanonicalizeTable5Size = 95;
static const int32_t kEcma262CanonicalizeTable5[190] = {
    1601, -4, 1603, -4, 1605, -4, 1607, -4, 1609, -4, 1611, -4, 1613, -4,
    1615, -4, 1617, -4, 1619, -4, 1621, -4, 1623, -4, 1625, -4, 1627, -4,
    1629, -4, 1631, -4, 1633, -4, 1635, -4, 1637, -4, 1639, -4, 1641, -4,
    1643, -4, 1645, -4, 1665, -4, 1667, -4, 1669, -4, 1671, -4, 1673, -4,
    1675, -4, 1677, -4, 1679, -4, 1681, -4, 1683, -4, 1685, -4, 1687, -4,
    1689, -4, 1691, -4, 1827, -4, 1829, -4, 1831, -4, 1833, -4, 1835, -4,
    1837, -4, 1839, -4, 1843, -4, 1845, -4, 1847, -4, 1849, -4, 1851, -4,
    1853, -4, 1855, -4, 1857, -4, 1859, -4, 1861, -4, 1863, -4, 1865, -4,
    1867, -4, 1869, -4, 1871, -4, 1873, -4, 1875, -4, 1877, -4, 1879, -4,
    1881, -4, 1883, -4, 1885, -4, 1887, -4, 1889, -4, 1891, -4, 1893, -4,
    1895, -4, 1897, -4, 1899, -4, 1901, -4, 1903, -4, 1914, -4, 1916, -4,
    1919, -4, 1921, -4, 1923, -4, 1925, -4, 1927, -4, 1932, -4, 1937, -4,
    1939, -4, 1943, -4, 1945, -4, 1947, -4, 1949, -4, 1951, -4, 1953, -4,
    1955, -4, 1957, -4, 1959, -4, 1961, -4};
static const uint16_t kEcma262CanonicalizeMultiStrings5Size = 1;
static const MultiCharacterSpecialCase<1> kEcma262CanonicalizeMultiStrings7[1] =
    {{{kSentinel}}};
static const uint16_t kEcma262CanonicalizeTable7Size = 2;
static const int32_t kEcma262CanonicalizeTable7[4] = {1073749825, -128, 8026,
                                                      -128};
static const uint16_t kEcma262CanonicalizeMultiStrings7Size = 1;
int Ecma262Canonicalize::Convert(uchar c, uchar n, uchar* result,
                                 bool* allow_caching_ptr) {
  int chunk_index = c >> 13;
  switch (chunk_index) {
    case 0:
      return LookupMapping<true>(
          kEcma262CanonicalizeTable0, kEcma262CanonicalizeTable0Size,
          kEcma262CanonicalizeMultiStrings0, c, n, result, allow_caching_ptr);
    case 1:
      return LookupMapping<true>(
          kEcma262CanonicalizeTable1, kEcma262CanonicalizeTable1Size,
          kEcma262CanonicalizeMultiStrings1, c, n, result, allow_caching_ptr);
    case 5:
      return LookupMapping<true>(
          kEcma262CanonicalizeTable5, kEcma262CanonicalizeTable5Size,
          kEcma262CanonicalizeMultiStrings5, c, n, result, allow_caching_ptr);
    case 7:
      return LookupMapping<true>(
          kEcma262CanonicalizeTable7, kEcma262CanonicalizeTable7Size,
          kEcma262CanonicalizeMultiStrings7, c, n, result, allow_caching_ptr);
    default:
      return 0;
  }
}

static const MultiCharacterSpecialCase<4>
    kEcma262UnCanonicalizeMultiStrings0[507] = {{{65, 97, kSentinel}},
                                                {{90, 122, kSentinel}},
                                                {{181, 924, 956, kSentinel}},
                                                {{192, 224, kSentinel}},
                                                {{214, 246, kSentinel}},
                                                {{216, 248, kSentinel}},
                                                {{222, 254, kSentinel}},
                                                {{255, 376, kSentinel}},
                                                {{256, 257, kSentinel}},
                                                {{258, 259, kSentinel}},
                                                {{260, 261, kSentinel}},
                                                {{262, 263, kSentinel}},
                                                {{264, 265, kSentinel}},
                                                {{266, 267, kSentinel}},
                                                {{268, 269, kSentinel}},
                                                {{270, 271, kSentinel}},
                                                {{272, 273, kSentinel}},
                                                {{274, 275, kSentinel}},
                                                {{276, 277, kSentinel}},
                                                {{278, 279, kSentinel}},
                                                {{280, 281, kSentinel}},
                                                {{282, 283, kSentinel}},
                                                {{284, 285, kSentinel}},
                                                {{286, 287, kSentinel}},
                                                {{288, 289, kSentinel}},
                                                {{290, 291, kSentinel}},
                                                {{292, 293, kSentinel}},
                                                {{294, 295, kSentinel}},
                                                {{296, 297, kSentinel}},
                                                {{298, 299, kSentinel}},
                                                {{300, 301, kSentinel}},
                                                {{302, 303, kSentinel}},
                                                {{306, 307, kSentinel}},
                                                {{308, 309, kSentinel}},
                                                {{310, 311, kSentinel}},
                                                {{313, 314, kSentinel}},
                                                {{315, 316, kSentinel}},
                                                {{317, 318, kSentinel}},
                                                {{319, 320, kSentinel}},
                                                {{321, 322, kSentinel}},
                                                {{323, 324, kSentinel}},
                                                {{325, 326, kSentinel}},
                                                {{327, 328, kSentinel}},
                                                {{330, 331, kSentinel}},
                                                {{332, 333, kSentinel}},
                                                {{334, 335, kSentinel}},
                                                {{336, 337, kSentinel}},
                                                {{338, 339, kSentinel}},
                                                {{340, 341, kSentinel}},
                                                {{342, 343, kSentinel}},
                                                {{344, 345, kSentinel}},
                                                {{346, 347, kSentinel}},
                                                {{348, 349, kSentinel}},
                                                {{350, 351, kSentinel}},
                                                {{352, 353, kSentinel}},
                                                {{354, 355, kSentinel}},
                                                {{356, 357, kSentinel}},
                                                {{358, 359, kSentinel}},
                                                {{360, 361, kSentinel}},
                                                {{362, 363, kSentinel}},
                                                {{364, 365, kSentinel}},
                                                {{366, 367, kSentinel}},
                                                {{368, 369, kSentinel}},
                                                {{370, 371, kSentinel}},
                                                {{372, 373, kSentinel}},
                                                {{374, 375, kSentinel}},
                                                {{377, 378, kSentinel}},
                                                {{379, 380, kSentinel}},
                                                {{381, 382, kSentinel}},
                                                {{384, 579, kSentinel}},
                                                {{385, 595, kSentinel}},
                                                {{386, 387, kSentinel}},
                                                {{388, 389, kSentinel}},
                                                {{390, 596, kSentinel}},
                                                {{391, 392, kSent
"""


```