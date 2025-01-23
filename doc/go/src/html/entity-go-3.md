Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding & Context:**

* **The Goal:** The request asks for the functionality of the provided Go code, which is located at `go/src/html/entity.go`. This immediately suggests it's related to HTML entity handling.
* **The Code:** The code consists of two Go maps: `entity` and `entity2`. The keys are strings, and the values are runes (for `entity`) and arrays of two runes (for `entity2`).
* **The Naming:**  The names "entity" and "entity2" are suggestive of representing HTML entities. The values being runes strongly imply a mapping from entity names to their Unicode characters. The `entity2` map, having two runes, hints at combined characters or base character + combining mark.
* **The Comment:** The `TODO(nigeltao)` comment in `entity2` explicitly mentions "replacements that are wider than their names."  This confirms the suspicion that `entity2` deals with more complex entity representations.

**2. Deeper Analysis of `entity`:**

* **Structure:** The `entity` map is a straightforward key-value store.
* **Content:** The keys look like standard HTML entity names (e.g., `&nbsp;`, `&lt;`, `&aacute;`). The values are single Unicode characters.
* **Functionality (Inference):**  It's highly likely this map is used to convert HTML entity names into their corresponding Unicode characters. This is a common task in HTML parsing and processing.

**3. Deeper Analysis of `entity2`:**

* **Structure:** The `entity2` map also uses string keys (entity names), but the values are arrays of two runes.
* **Content:** The keys again resemble entity names. The values look like base characters followed by combining characters (e.g., `'\u2242', '\u0338'` for "NotEqualTilde;", where `\u0338` is a combining slash).
* **Functionality (Inference):** This map likely handles HTML entities that require more than one Unicode code point to represent correctly. This often involves a base character and a combining mark (like a diacritic or a stroke).

**4. Hypothesizing the Overall Purpose:**

Combining the analyses of both maps, the core functionality of this code is to provide a comprehensive mapping of HTML entity names to their Unicode representations, handling both simple single-character entities and more complex multi-character ones.

**5. Constructing the Go Code Example:**

* **Need:**  Demonstrate how this data structure would be used.
* **Core Operation:** The primary use case is likely to look up an entity name and retrieve its character(s).
* **Implementation:**  A simple function that takes an entity name as input and checks both maps is a good way to illustrate this. The function should return the corresponding rune(s) or an indication if the entity isn't found.

```go
package main

import "fmt"

// ... (The provided entity and entity2 maps would go here) ...

func main() {
	entityMap, entityMap2 := getEntityMaps() // Assume the provided code is within this function

	testEntities := []string{"nbsp", "lt", "aacute", "NotEqualTilde", "fjlig"}

	for _, entityName := range testEntities {
		if r, ok := entityMap[entityName+";"]; ok { // Add semicolon for full entity name
			fmt.Printf("Entity: &%s; -> Rune: %c\n", entityName, r)
		} else if runearray, ok := entityMap2[entityName+";"]; ok { // Add semicolon
			fmt.Printf("Entity: &%s; -> Runes: %c%c\n", entityName, runearray[0], runearray[1])
		} else {
			fmt.Printf("Entity: &%s; not found\n", entityName)
		}
	}
}

func getEntityMaps() (map[string]rune, map[string][2]rune) {
	// ... (The provided code snippet goes here) ...
}
```

* **Input/Output:** The example uses a list of entity names to test the lookup process, demonstrating how the function would retrieve the corresponding characters.

**6. Identifying Potential Pitfalls (User Errors):**

* **Case Sensitivity:** HTML entity names are case-sensitive. Users might incorrectly assume they are not.
* **Missing Semicolon:** Entity names in HTML *must* end with a semicolon. Forgetting this is a common mistake.
* **Incorrect Entity Name:** Typos or using non-standard entity names will lead to lookup failures.

**7. Addressing Command Line Arguments (Not Applicable):**

The provided code snippet is just data structures (maps). It doesn't directly handle command-line arguments. Therefore, this part of the request is skipped.

**8. Summarizing the Functionality (Conclusion):**

Based on the analysis, the primary function of this code is to provide a lookup mechanism for HTML entity names, mapping them to their corresponding Unicode character(s). It's a crucial component for HTML parsing and rendering, enabling the correct display of special characters.

This structured approach, moving from high-level understanding to detailed analysis and finally to practical examples and potential issues, allows for a comprehensive and accurate answer to the request.
这是提供的Go语言代码片段的最后一部分，它定义了两个 Go 语言的 map 类型的变量，用于存储 HTML 实体及其对应的 Unicode 字符。结合之前提供的部分，我们可以归纳出 `go/src/html/entity.go` 文件的完整功能。

**归纳其功能：**

`go/src/html/entity.go` 文件的主要功能是提供 HTML 实体名称到 Unicode 字符的映射。它包含了两个 map：

1. **`entity` ( `map[string]rune` )：**  存储了大部分常用的 HTML 实体名称及其对应的单个 Unicode 字符。键是 HTML 实体名称（例如 `"&nbsp;"`），值是对应的 Unicode 字符（例如 `'\u00A0'`，表示不间断空格）。

2. **`entity2` ( `map[string][2]rune` )：** 存储了那些需要用两个 Unicode 字符来表示的 HTML 实体。这种情况通常发生在某些数学符号或者带有组合字符的实体上。键是 HTML 实体名称，值是一个包含两个 `rune` 的数组。例如，`"NotEqualTilde;"` 对应 `'\u2242'` (波浪线等于) 和 `'\u0338'` (组合斜线，用于表示“不”)。

**总而言之，`go/src/html/entity.go` 文件实现了一个 HTML 实体解码器所需的查找表，可以将 HTML 文档中出现的实体名称转换为其对应的 Unicode 字符，以便正确地解析和渲染 HTML 内容。**

**功能列举：**

* **提供 HTML 实体到 Unicode 字符的映射:** 这是核心功能，允许程序将 HTML 中的 `&nbsp;` 转换为实际的空格字符。
* **处理常用的 HTML 实体:** `entity` map 包含了大量的常用实体，覆盖了基本 Latin 字符、符号以及一些特殊字符。
* **处理需要多个 Unicode 字符表示的实体:** `entity2` map 解决了某些复杂实体的表示问题，例如带删除线的符号。

**它是什么 Go 语言功能的实现？**

这个文件是 Go 语言标准库中 `html` 包的一部分，用于实现 **HTML 实体解码（HTML Entity Decoding）** 功能。当解析 HTML 文档时，遇到类似 `&nbsp;` 这样的实体引用，就需要将其转换回其代表的实际字符。`entity.go` 文件就提供了这个转换所需的映射数据。

**Go 代码举例说明：**

虽然 `entity.go` 本身只是数据定义，但我们可以演示如何在 Go 代码中使用这些映射来进行实体解码。假设我们有以下 HTML 片段：

```html
<p>这是一个&nbsp;示例，其中包含&lt;和&gt;符号。</p>
```

我们可以使用 `html` 包中的相关函数和 `entity.go` 中定义的数据来解码这个片段：

```go
package main

import (
	"fmt"
	"html"
)

func main() {
	encodedHTML := "<p>这是一个&nbsp;示例，其中包含&lt;和&gt;符号。</p>"
	decodedHTML := html.UnescapeString(encodedHTML)
	fmt.Println(decodedHTML)
}
```

**假设的输入与输出：**

* **输入 (encodedHTML):**  `"<p>这是一个&nbsp;示例，其中包含&lt;和&gt;符号。</p>"`
* **输出 (decodedHTML):** `"<p>这是一个 示例，其中包含<和>符号。</p>"`

在这个例子中，`html.UnescapeString` 函数会使用类似 `entity.go` 中定义的映射来将 `&nbsp;` 转换为空格，`&lt;` 转换为 `<`，`&gt;` 转换为 `>`。

**命令行参数的具体处理：**

`entity.go` 文件本身并不处理命令行参数。它是 `html` 包的内部数据文件，由其他处理 HTML 的 Go 代码使用。如果要处理包含 HTML 实体的命令行参数，你需要编写 Go 代码来读取这些参数，并使用 `html.UnescapeString` 或类似的函数进行解码。

**使用者易犯错的点：**

* **大小写敏感性：** HTML 实体名称是大小写敏感的。例如，`&NBSP;` 和 `&nbsp;` 是不同的，只有小写的 `&nbsp;` 是正确的。如果用户错误地输入了大写或其他拼写错误的实体名称，解码器将无法识别。

   **错误示例：**
   ```go
   package main

   import (
   	"fmt"
   	"html"
   )

   func main() {
   	encoded := "&NBSP;" // 错误地使用大写
   	decoded := html.UnescapeString(encoded)
   	fmt.Printf("Encoded: %s\n", encoded)
   	fmt.Printf("Decoded: %s\n", decoded) // 输出仍然是 &NBSP;，因为无法识别
   }
   ```

* **忘记分号：** HTML 实体必须以分号 `;` 结尾。如果忘记分号，解码器也无法正确识别实体。

   **错误示例：**
   ```go
   package main

   import (
   	"fmt"
   	"html"
   )

   func main() {
   	encoded := "&nbsp" // 忘记了分号
   	decoded := html.UnescapeString(encoded)
   	fmt.Printf("Encoded: %s\n", encoded)
   	fmt.Printf("Decoded: %s\n", decoded) // 输出仍然是 &nbsp，因为无法识别
   }
   ```

总而言之，`go/src/html/entity.go` 是 Go 语言处理 HTML 内容的基础组成部分，它通过提供实体名称到字符的映射，使得 Go 程序能够正确地解析和显示包含 HTML 实体的文本。

### 提示词
```
这是路径为go/src/html/entity.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```go
own;":                    '\U000025BF',
		"triangleleft;":                    '\U000025C3',
		"trianglelefteq;":                  '\U000022B4',
		"triangleq;":                       '\U0000225C',
		"triangleright;":                   '\U000025B9',
		"trianglerighteq;":                 '\U000022B5',
		"tridot;":                          '\U000025EC',
		"trie;":                            '\U0000225C',
		"triminus;":                        '\U00002A3A',
		"triplus;":                         '\U00002A39',
		"trisb;":                           '\U000029CD',
		"tritime;":                         '\U00002A3B',
		"trpezium;":                        '\U000023E2',
		"tscr;":                            '\U0001D4C9',
		"tscy;":                            '\U00000446',
		"tshcy;":                           '\U0000045B',
		"tstrok;":                          '\U00000167',
		"twixt;":                           '\U0000226C',
		"twoheadleftarrow;":                '\U0000219E',
		"twoheadrightarrow;":               '\U000021A0',
		"uArr;":                            '\U000021D1',
		"uHar;":                            '\U00002963',
		"uacute;":                          '\U000000FA',
		"uarr;":                            '\U00002191',
		"ubrcy;":                           '\U0000045E',
		"ubreve;":                          '\U0000016D',
		"ucirc;":                           '\U000000FB',
		"ucy;":                             '\U00000443',
		"udarr;":                           '\U000021C5',
		"udblac;":                          '\U00000171',
		"udhar;":                           '\U0000296E',
		"ufisht;":                          '\U0000297E',
		"ufr;":                             '\U0001D532',
		"ugrave;":                          '\U000000F9',
		"uharl;":                           '\U000021BF',
		"uharr;":                           '\U000021BE',
		"uhblk;":                           '\U00002580',
		"ulcorn;":                          '\U0000231C',
		"ulcorner;":                        '\U0000231C',
		"ulcrop;":                          '\U0000230F',
		"ultri;":                           '\U000025F8',
		"umacr;":                           '\U0000016B',
		"uml;":                             '\U000000A8',
		"uogon;":                           '\U00000173',
		"uopf;":                            '\U0001D566',
		"uparrow;":                         '\U00002191',
		"updownarrow;":                     '\U00002195',
		"upharpoonleft;":                   '\U000021BF',
		"upharpoonright;":                  '\U000021BE',
		"uplus;":                           '\U0000228E',
		"upsi;":                            '\U000003C5',
		"upsih;":                           '\U000003D2',
		"upsilon;":                         '\U000003C5',
		"upuparrows;":                      '\U000021C8',
		"urcorn;":                          '\U0000231D',
		"urcorner;":                        '\U0000231D',
		"urcrop;":                          '\U0000230E',
		"uring;":                           '\U0000016F',
		"urtri;":                           '\U000025F9',
		"uscr;":                            '\U0001D4CA',
		"utdot;":                           '\U000022F0',
		"utilde;":                          '\U00000169',
		"utri;":                            '\U000025B5',
		"utrif;":                           '\U000025B4',
		"uuarr;":                           '\U000021C8',
		"uuml;":                            '\U000000FC',
		"uwangle;":                         '\U000029A7',
		"vArr;":                            '\U000021D5',
		"vBar;":                            '\U00002AE8',
		"vBarv;":                           '\U00002AE9',
		"vDash;":                           '\U000022A8',
		"vangrt;":                          '\U0000299C',
		"varepsilon;":                      '\U000003F5',
		"varkappa;":                        '\U000003F0',
		"varnothing;":                      '\U00002205',
		"varphi;":                          '\U000003D5',
		"varpi;":                           '\U000003D6',
		"varpropto;":                       '\U0000221D',
		"varr;":                            '\U00002195',
		"varrho;":                          '\U000003F1',
		"varsigma;":                        '\U000003C2',
		"vartheta;":                        '\U000003D1',
		"vartriangleleft;":                 '\U000022B2',
		"vartriangleright;":                '\U000022B3',
		"vcy;":                             '\U00000432',
		"vdash;":                           '\U000022A2',
		"vee;":                             '\U00002228',
		"veebar;":                          '\U000022BB',
		"veeeq;":                           '\U0000225A',
		"vellip;":                          '\U000022EE',
		"verbar;":                          '\U0000007C',
		"vert;":                            '\U0000007C',
		"vfr;":                             '\U0001D533',
		"vltri;":                           '\U000022B2',
		"vopf;":                            '\U0001D567',
		"vprop;":                           '\U0000221D',
		"vrtri;":                           '\U000022B3',
		"vscr;":                            '\U0001D4CB',
		"vzigzag;":                         '\U0000299A',
		"wcirc;":                           '\U00000175',
		"wedbar;":                          '\U00002A5F',
		"wedge;":                           '\U00002227',
		"wedgeq;":                          '\U00002259',
		"weierp;":                          '\U00002118',
		"wfr;":                             '\U0001D534',
		"wopf;":                            '\U0001D568',
		"wp;":                              '\U00002118',
		"wr;":                              '\U00002240',
		"wreath;":                          '\U00002240',
		"wscr;":                            '\U0001D4CC',
		"xcap;":                            '\U000022C2',
		"xcirc;":                           '\U000025EF',
		"xcup;":                            '\U000022C3',
		"xdtri;":                           '\U000025BD',
		"xfr;":                             '\U0001D535',
		"xhArr;":                           '\U000027FA',
		"xharr;":                           '\U000027F7',
		"xi;":                              '\U000003BE',
		"xlArr;":                           '\U000027F8',
		"xlarr;":                           '\U000027F5',
		"xmap;":                            '\U000027FC',
		"xnis;":                            '\U000022FB',
		"xodot;":                           '\U00002A00',
		"xopf;":                            '\U0001D569',
		"xoplus;":                          '\U00002A01',
		"xotime;":                          '\U00002A02',
		"xrArr;":                           '\U000027F9',
		"xrarr;":                           '\U000027F6',
		"xscr;":                            '\U0001D4CD',
		"xsqcup;":                          '\U00002A06',
		"xuplus;":                          '\U00002A04',
		"xutri;":                           '\U000025B3',
		"xvee;":                            '\U000022C1',
		"xwedge;":                          '\U000022C0',
		"yacute;":                          '\U000000FD',
		"yacy;":                            '\U0000044F',
		"ycirc;":                           '\U00000177',
		"ycy;":                             '\U0000044B',
		"yen;":                             '\U000000A5',
		"yfr;":                             '\U0001D536',
		"yicy;":                            '\U00000457',
		"yopf;":                            '\U0001D56A',
		"yscr;":                            '\U0001D4CE',
		"yucy;":                            '\U0000044E',
		"yuml;":                            '\U000000FF',
		"zacute;":                          '\U0000017A',
		"zcaron;":                          '\U0000017E',
		"zcy;":                             '\U00000437',
		"zdot;":                            '\U0000017C',
		"zeetrf;":                          '\U00002128',
		"zeta;":                            '\U000003B6',
		"zfr;":                             '\U0001D537',
		"zhcy;":                            '\U00000436',
		"zigrarr;":                         '\U000021DD',
		"zopf;":                            '\U0001D56B',
		"zscr;":                            '\U0001D4CF',
		"zwj;":                             '\U0000200D',
		"zwnj;":                            '\U0000200C',
		"AElig":                            '\U000000C6',
		"AMP":                              '\U00000026',
		"Aacute":                           '\U000000C1',
		"Acirc":                            '\U000000C2',
		"Agrave":                           '\U000000C0',
		"Aring":                            '\U000000C5',
		"Atilde":                           '\U000000C3',
		"Auml":                             '\U000000C4',
		"COPY":                             '\U000000A9',
		"Ccedil":                           '\U000000C7',
		"ETH":                              '\U000000D0',
		"Eacute":                           '\U000000C9',
		"Ecirc":                            '\U000000CA',
		"Egrave":                           '\U000000C8',
		"Euml":                             '\U000000CB',
		"GT":                               '\U0000003E',
		"Iacute":                           '\U000000CD',
		"Icirc":                            '\U000000CE',
		"Igrave":                           '\U000000CC',
		"Iuml":                             '\U000000CF',
		"LT":                               '\U0000003C',
		"Ntilde":                           '\U000000D1',
		"Oacute":                           '\U000000D3',
		"Ocirc":                            '\U000000D4',
		"Ograve":                           '\U000000D2',
		"Oslash":                           '\U000000D8',
		"Otilde":                           '\U000000D5',
		"Ouml":                             '\U000000D6',
		"QUOT":                             '\U00000022',
		"REG":                              '\U000000AE',
		"THORN":                            '\U000000DE',
		"Uacute":                           '\U000000DA',
		"Ucirc":                            '\U000000DB',
		"Ugrave":                           '\U000000D9',
		"Uuml":                             '\U000000DC',
		"Yacute":                           '\U000000DD',
		"aacute":                           '\U000000E1',
		"acirc":                            '\U000000E2',
		"acute":                            '\U000000B4',
		"aelig":                            '\U000000E6',
		"agrave":                           '\U000000E0',
		"amp":                              '\U00000026',
		"aring":                            '\U000000E5',
		"atilde":                           '\U000000E3',
		"auml":                             '\U000000E4',
		"brvbar":                           '\U000000A6',
		"ccedil":                           '\U000000E7',
		"cedil":                            '\U000000B8',
		"cent":                             '\U000000A2',
		"copy":                             '\U000000A9',
		"curren":                           '\U000000A4',
		"deg":                              '\U000000B0',
		"divide":                           '\U000000F7',
		"eacute":                           '\U000000E9',
		"ecirc":                            '\U000000EA',
		"egrave":                           '\U000000E8',
		"eth":                              '\U000000F0',
		"euml":                             '\U000000EB',
		"frac12":                           '\U000000BD',
		"frac14":                           '\U000000BC',
		"frac34":                           '\U000000BE',
		"gt":                               '\U0000003E',
		"iacute":                           '\U000000ED',
		"icirc":                            '\U000000EE',
		"iexcl":                            '\U000000A1',
		"igrave":                           '\U000000EC',
		"iquest":                           '\U000000BF',
		"iuml":                             '\U000000EF',
		"laquo":                            '\U000000AB',
		"lt":                               '\U0000003C',
		"macr":                             '\U000000AF',
		"micro":                            '\U000000B5',
		"middot":                           '\U000000B7',
		"nbsp":                             '\U000000A0',
		"not":                              '\U000000AC',
		"ntilde":                           '\U000000F1',
		"oacute":                           '\U000000F3',
		"ocirc":                            '\U000000F4',
		"ograve":                           '\U000000F2',
		"ordf":                             '\U000000AA',
		"ordm":                             '\U000000BA',
		"oslash":                           '\U000000F8',
		"otilde":                           '\U000000F5',
		"ouml":                             '\U000000F6',
		"para":                             '\U000000B6',
		"plusmn":                           '\U000000B1',
		"pound":                            '\U000000A3',
		"quot":                             '\U00000022',
		"raquo":                            '\U000000BB',
		"reg":                              '\U000000AE',
		"sect":                             '\U000000A7',
		"shy":                              '\U000000AD',
		"sup1":                             '\U000000B9',
		"sup2":                             '\U000000B2',
		"sup3":                             '\U000000B3',
		"szlig":                            '\U000000DF',
		"thorn":                            '\U000000FE',
		"times":                            '\U000000D7',
		"uacute":                           '\U000000FA',
		"ucirc":                            '\U000000FB',
		"ugrave":                           '\U000000F9',
		"uml":                              '\U000000A8',
		"uuml":                             '\U000000FC',
		"yacute":                           '\U000000FD',
		"yen":                              '\U000000A5',
		"yuml":                             '\U000000FF',
	}

	entity2 = map[string][2]rune{
		// TODO(nigeltao): Handle replacements that are wider than their names.
		// "nLt;":                     {'\u226A', '\u20D2'},
		// "nGt;":                     {'\u226B', '\u20D2'},
		"NotEqualTilde;":           {'\u2242', '\u0338'},
		"NotGreaterFullEqual;":     {'\u2267', '\u0338'},
		"NotGreaterGreater;":       {'\u226B', '\u0338'},
		"NotGreaterSlantEqual;":    {'\u2A7E', '\u0338'},
		"NotHumpDownHump;":         {'\u224E', '\u0338'},
		"NotHumpEqual;":            {'\u224F', '\u0338'},
		"NotLeftTriangleBar;":      {'\u29CF', '\u0338'},
		"NotLessLess;":             {'\u226A', '\u0338'},
		"NotLessSlantEqual;":       {'\u2A7D', '\u0338'},
		"NotNestedGreaterGreater;": {'\u2AA2', '\u0338'},
		"NotNestedLessLess;":       {'\u2AA1', '\u0338'},
		"NotPrecedesEqual;":        {'\u2AAF', '\u0338'},
		"NotRightTriangleBar;":     {'\u29D0', '\u0338'},
		"NotSquareSubset;":         {'\u228F', '\u0338'},
		"NotSquareSuperset;":       {'\u2290', '\u0338'},
		"NotSubset;":               {'\u2282', '\u20D2'},
		"NotSucceedsEqual;":        {'\u2AB0', '\u0338'},
		"NotSucceedsTilde;":        {'\u227F', '\u0338'},
		"NotSuperset;":             {'\u2283', '\u20D2'},
		"ThickSpace;":              {'\u205F', '\u200A'},
		"acE;":                     {'\u223E', '\u0333'},
		"bne;":                     {'\u003D', '\u20E5'},
		"bnequiv;":                 {'\u2261', '\u20E5'},
		"caps;":                    {'\u2229', '\uFE00'},
		"cups;":                    {'\u222A', '\uFE00'},
		"fjlig;":                   {'\u0066', '\u006A'},
		"gesl;":                    {'\u22DB', '\uFE00'},
		"gvertneqq;":               {'\u2269', '\uFE00'},
		"gvnE;":                    {'\u2269', '\uFE00'},
		"lates;":                   {'\u2AAD', '\uFE00'},
		"lesg;":                    {'\u22DA', '\uFE00'},
		"lvertneqq;":               {'\u2268', '\uFE00'},
		"lvnE;":                    {'\u2268', '\uFE00'},
		"nGg;":                     {'\u22D9', '\u0338'},
		"nGtv;":                    {'\u226B', '\u0338'},
		"nLl;":                     {'\u22D8', '\u0338'},
		"nLtv;":                    {'\u226A', '\u0338'},
		"nang;":                    {'\u2220', '\u20D2'},
		"napE;":                    {'\u2A70', '\u0338'},
		"napid;":                   {'\u224B', '\u0338'},
		"nbump;":                   {'\u224E', '\u0338'},
		"nbumpe;":                  {'\u224F', '\u0338'},
		"ncongdot;":                {'\u2A6D', '\u0338'},
		"nedot;":                   {'\u2250', '\u0338'},
		"nesim;":                   {'\u2242', '\u0338'},
		"ngE;":                     {'\u2267', '\u0338'},
		"ngeqq;":                   {'\u2267', '\u0338'},
		"ngeqslant;":               {'\u2A7E', '\u0338'},
		"nges;":                    {'\u2A7E', '\u0338'},
		"nlE;":                     {'\u2266', '\u0338'},
		"nleqq;":                   {'\u2266', '\u0338'},
		"nleqslant;":               {'\u2A7D', '\u0338'},
		"nles;":                    {'\u2A7D', '\u0338'},
		"notinE;":                  {'\u22F9', '\u0338'},
		"notindot;":                {'\u22F5', '\u0338'},
		"nparsl;":                  {'\u2AFD', '\u20E5'},
		"npart;":                   {'\u2202', '\u0338'},
		"npre;":                    {'\u2AAF', '\u0338'},
		"npreceq;":                 {'\u2AAF', '\u0338'},
		"nrarrc;":                  {'\u2933', '\u0338'},
		"nrarrw;":                  {'\u219D', '\u0338'},
		"nsce;":                    {'\u2AB0', '\u0338'},
		"nsubE;":                   {'\u2AC5', '\u0338'},
		"nsubset;":                 {'\u2282', '\u20D2'},
		"nsubseteqq;":              {'\u2AC5', '\u0338'},
		"nsucceq;":                 {'\u2AB0', '\u0338'},
		"nsupE;":                   {'\u2AC6', '\u0338'},
		"nsupset;":                 {'\u2283', '\u20D2'},
		"nsupseteqq;":              {'\u2AC6', '\u0338'},
		"nvap;":                    {'\u224D', '\u20D2'},
		"nvge;":                    {'\u2265', '\u20D2'},
		"nvgt;":                    {'\u003E', '\u20D2'},
		"nvle;":                    {'\u2264', '\u20D2'},
		"nvlt;":                    {'\u003C', '\u20D2'},
		"nvltrie;":                 {'\u22B4', '\u20D2'},
		"nvrtrie;":                 {'\u22B5', '\u20D2'},
		"nvsim;":                   {'\u223C', '\u20D2'},
		"race;":                    {'\u223D', '\u0331'},
		"smtes;":                   {'\u2AAC', '\uFE00'},
		"sqcaps;":                  {'\u2293', '\uFE00'},
		"sqcups;":                  {'\u2294', '\uFE00'},
		"varsubsetneq;":            {'\u228A', '\uFE00'},
		"varsubsetneqq;":           {'\u2ACB', '\uFE00'},
		"varsupsetneq;":            {'\u228B', '\uFE00'},
		"varsupsetneqq;":           {'\u2ACC', '\uFE00'},
		"vnsub;":                   {'\u2282', '\u20D2'},
		"vnsup;":                   {'\u2283', '\u20D2'},
		"vsubnE;":                  {'\u2ACB', '\uFE00'},
		"vsubne;":                  {'\u228A', '\uFE00'},
		"vsupnE;":                  {'\u2ACC', '\uFE00'},
		"vsupne;":                  {'\u228B', '\uFE00'},
	}

	return entity, entity2
})
```