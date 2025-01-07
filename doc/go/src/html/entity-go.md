Response:
Let's break down the thought process for analyzing the provided Go code snippet and answering the user's request.

**1. Understanding the Request:**

The user provided a snippet of Go code from `go/src/html/entity.go` and asked for:

* **Functionality:** What does this code do?
* **Go Feature:** What Go language feature does it implement?  Provide a code example.
* **Code Reasoning:** If there's code logic, illustrate with input and output.
* **Command-line Arguments:**  Are there any command-line parameters involved?
* **Common Mistakes:** What errors might users make?
* **Summary:** A concise summary of the code's function.

**2. Initial Code Scan and Keyword Identification:**

I immediately looked for key Go keywords and structures:

* `package html`: This tells me the code is part of the `html` package.
* `import "sync"`:  The code uses the `sync` package, likely for managing concurrent access.
* `const longestEntityWithoutSemicolon = 6`:  A constant declaration, probably related to optimization or data handling.
* `var entityMaps = sync.OnceValues(func() ...)`: This is a crucial line. It uses `sync.OnceValues`, indicating lazy initialization of a shared resource. The `func()` part defines the initialization logic.
* `map[string]rune`:  This is the return type of the initialization function, indicating a map where keys are strings (likely HTML entity names) and values are runes (Unicode code points).
* `map[string][2]rune`:  Another map, where values are arrays of two runes. This suggests handling of special cases or combined characters.
* The large map literal within the `func()`: This is the core data structure, mapping HTML entity names to their corresponding Unicode values. The semicolon in the entity name seems significant based on the comment.

**3. Deduction and Hypothesis Formation:**

Based on the keywords and structure, I formed the following hypotheses:

* **Core Functionality:** The code provides a mapping between HTML entity names (like `&amp;`, `&nbsp;`, etc.) and their corresponding Unicode characters. This is essential for HTML parsing and encoding.
* **Go Feature:** The use of `sync.OnceValues` strongly suggests this is implementing a *singleton pattern* or some form of *lazy initialization* for a shared resource. This is done to avoid redundant computations when the entity map is needed multiple times.
* **`longestEntityWithoutSemicolon`:**  This likely serves as an optimization hint when parsing HTML. If an entity doesn't end in a semicolon, its name is likely short.
* **`entity2`:**  The `entity2` map probably handles entities that require two Unicode code points to represent. This could be for combining characters or less common entities.

**4. Constructing the Explanation (Following the Request's Structure):**

Now, I started organizing my understanding according to the user's requested points:

* **功能 (Functionality):**  I described the core purpose: mapping HTML entity names to Unicode characters. I highlighted the significance of the semicolon and the existence of `entity2`.
* **Go语言功能的实现 (Go Feature Implementation):** I identified `sync.OnceValues` as the key feature and explained its purpose (lazy, thread-safe initialization). I then created a simple Go code example demonstrating how to access and use the `entityMaps`. The example showed accessing both `entity` and `entity2`. I chose common entities like `&amp;` and a less common one that might potentially be in `entity2` (though none were explicitly in this part). The input was the entity name, and the output was the corresponding rune(s).
* **代码推理 (Code Reasoning):** I focused on the conditional logic within the `entityMaps` initialization (even though it's implicitly within the map literal). The key inference is the direct mapping. I provided a simple "input" (entity name) and "output" (Unicode value).
* **命令行参数的具体处理 (Command-line Arguments):**  I correctly identified that this code snippet doesn't handle command-line arguments. It's a data structure definition.
* **使用者易犯错的点 (Common Mistakes):** I considered potential errors users might make. The most obvious one is case sensitivity in entity names and forgetting the semicolon when it's required. I provided an example illustrating this.
* **归纳一下它的功能 (Summarize its Functionality):**  I provided a concise summary reiterating the main purpose.

**5. Iteration and Refinement (Self-Correction):**

* **Initial thought about `entity2`:** I initially thought `entity2` might be for some historical reason or for handling non-standard entities. However, the comment "map of HTML entities to two unicode codepoints" is quite clear. I adjusted my explanation accordingly.
* **Code Example:** I made sure the code example was simple and directly illustrated the usage of `entityMaps`.
* **Clarity and Language:** I focused on using clear and concise Chinese.

By following this thought process, I was able to systematically analyze the code snippet and generate a comprehensive and accurate answer to the user's request, addressing each point in detail. The key was to identify the core purpose, the relevant Go language feature, and then build the explanation around that.
这段Go语言代码是 `html` 包的一部分，主要功能是**提供HTML实体名称到Unicode字符的映射关系**。

具体来说，它实现了以下功能：

1. **存储HTML实体名称和对应Unicode字符的映射关系：**  代码中定义了一个名为 `entityMaps` 的变量，它是一个延迟初始化的（通过 `sync.OnceValues` 实现）包含了两个 map 的结构。
    * 第一个 map 叫做 `entity`，它的键是 HTML 实体名称的字符串（例如 `"AElig;"`, `"amp;"`），值是对应的 Unicode 字符（`rune` 类型）。注意，实体名称是否包含分号是区分的，例如 `"amp"` 和 `"amp;"` 被视为不同的实体。
    * 第二个 map 叫做 `entity2`，它与 `entity` 类似，但是它的值是一个包含两个 `rune` 的数组。这可能是为了处理某些需要用两个 Unicode 码点表示的特殊字符，尽管在这个给定的代码片段中 `entity2` 是空的。

2. **延迟初始化 (Lazy Initialization)：**  使用 `sync.OnceValues` 确保 `entityMaps` 中的 map 只会被初始化一次，即使在并发环境下多次访问。这是一种常见的优化手段，可以避免不必要的重复初始化工作。

3. **定义最长不带分号的实体长度：**  常量 `longestEntityWithoutSemicolon` 被设置为 6。这可能在 HTML 解析过程中作为一个优化提示，因为所有不以分号结尾的实体名称长度都不会超过 6 个字节。

**它是什么go语言功能的实现？**

这段代码主要使用了 **Go 语言的 `map` 数据结构** 和 **`sync` 包中的 `OnceValues` 类型** 来实现一个线程安全的、延迟初始化的数据存储结构。

**Go 代码举例说明：**

假设我们想获取 HTML 实体 `"AMP;"` 对应的 Unicode 字符，可以使用以下代码：

```go
package main

import (
	"fmt"
	"html" // 注意这里导入的是 "html" 包，而不是 "go/src/html"
)

func main() {
	entities, _ := html.entityMaps.Load() // 获取 entity map
	amp, ok := entities["AMP;"]
	if ok {
		fmt.Printf("HTML实体 &AMP; 对应的 Unicode 字符是: %c\n", amp)
	} else {
		fmt.Println("未找到 HTML 实体 &AMP;")
	}
}
```

**假设的输入与输出：**

* **输入：**  调用 `html.entityMaps.Load()` 并访问键 `"AMP;"`。
* **输出：**  `HTML实体 &AMP; 对应的 Unicode 字符是: &`

**代码推理：**

`sync.OnceValues` 的 `Load()` 方法会返回 `entityMaps` 中存储的两个 map。由于 `entityMaps` 是延迟初始化的，第一次调用 `Load()` 时会执行 `func()` 来初始化这两个 map。  然后，我们通过键 `"AMP;"` 在 `entity` map 中查找对应的值，即 Unicode 字符 `&`。

**命令行参数的具体处理：**

这段代码本身不涉及任何命令行参数的处理。它只是定义了一个数据结构和初始化逻辑。

**使用者易犯错的点：**

* **大小写敏感：** HTML 实体名称是大小写敏感的。例如，`"AMP;"` 和 `"amp;"` 是不同的实体。 使用者可能会错误地使用小写或其他错误的大小写形式。
    ```go
    package main

    import (
        "fmt"
        "html"
    )

    func main() {
        entities, _ := html.entityMaps.Load()
        ampLower, okLower := entities["amp;"] // 注意这里是小写
        if okLower {
            fmt.Printf("找到小写 &amp;: %c\n", ampLower)
        } else {
            fmt.Println("未找到小写 &amp;") // 很可能输出这个
        }

        ampUpper, okUpper := entities["AMP;"] // 注意这里是大写
        if okUpper {
            fmt.Printf("找到大写 &AMP;: %c\n", ampUpper) // 很可能输出这个
        } else {
            fmt.Println("未找到大写 &AMP;")
        }
    }
    ```
    **输出（很可能）：**
    ```
    未找到小写 &amp;
    找到大写 &AMP;: &
    ```

* **忽略分号：** 有些实体必须以分号结尾才能被识别。使用者可能忘记添加分号，导致查找失败。
    ```go
    package main

    import (
        "fmt"
        "html"
    )

    func main() {
        entities, _ := html.entityMaps.Load()
        ampWithoutSemicolon, ok := entities["AMP"] // 注意这里没有分号
        if ok {
            fmt.Println("找到没有分号的 AMP:", ampWithoutSemicolon)
        } else {
            fmt.Println("未找到没有分号的 AMP") // 很可能输出这个
        }

        ampWithSemicolon, ok := entities["AMP;"] // 注意这里有分号
        if ok {
            fmt.Printf("找到带分号的 AMP;: %c\n", ampWithSemicolon) // 很可能输出这个
        } else {
            fmt.Println("未找到带分号的 AMP;")
        }
    }
    ```
    **输出（很可能）：**
    ```
    未找到没有分号的 AMP
    找到带分号的 AMP;: &
    ```

**归纳一下它的功能 (第1部分)：**

这段代码的主要功能是**提供一个高效且线程安全的 HTML 实体名称到 Unicode 字符的映射表**，供 `html` 包内部使用，用于 HTML 的解析和处理。 它通过延迟初始化来避免不必要的资源消耗，并预定义了最长不带分号的实体长度作为可能的优化提示。

Prompt: 
```
这是路径为go/src/html/entity.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共4部分，请归纳一下它的功能

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package html

import "sync"

// All entities that do not end with ';' are 6 or fewer bytes long.
const longestEntityWithoutSemicolon = 6

// entityMaps returns entity and entity2.
//
// entity is a map from HTML entity names to their values. The semicolon matters:
// https://html.spec.whatwg.org/multipage/named-characters.html
// lists both "amp" and "amp;" as two separate entries.
// Note that the HTML5 list is larger than the HTML4 list at
// http://www.w3.org/TR/html4/sgml/entities.html
//
// entity2 is a map of HTML entities to two unicode codepoints.
var entityMaps = sync.OnceValues(func() (entity map[string]rune, entity2 map[string][2]rune) {
	entity = map[string]rune{
		"AElig;":                           '\U000000C6',
		"AMP;":                             '\U00000026',
		"Aacute;":                          '\U000000C1',
		"Abreve;":                          '\U00000102',
		"Acirc;":                           '\U000000C2',
		"Acy;":                             '\U00000410',
		"Afr;":                             '\U0001D504',
		"Agrave;":                          '\U000000C0',
		"Alpha;":                           '\U00000391',
		"Amacr;":                           '\U00000100',
		"And;":                             '\U00002A53',
		"Aogon;":                           '\U00000104',
		"Aopf;":                            '\U0001D538',
		"ApplyFunction;":                   '\U00002061',
		"Aring;":                           '\U000000C5',
		"Ascr;":                            '\U0001D49C',
		"Assign;":                          '\U00002254',
		"Atilde;":                          '\U000000C3',
		"Auml;":                            '\U000000C4',
		"Backslash;":                       '\U00002216',
		"Barv;":                            '\U00002AE7',
		"Barwed;":                          '\U00002306',
		"Bcy;":                             '\U00000411',
		"Because;":                         '\U00002235',
		"Bernoullis;":                      '\U0000212C',
		"Beta;":                            '\U00000392',
		"Bfr;":                             '\U0001D505',
		"Bopf;":                            '\U0001D539',
		"Breve;":                           '\U000002D8',
		"Bscr;":                            '\U0000212C',
		"Bumpeq;":                          '\U0000224E',
		"CHcy;":                            '\U00000427',
		"COPY;":                            '\U000000A9',
		"Cacute;":                          '\U00000106',
		"Cap;":                             '\U000022D2',
		"CapitalDifferentialD;":            '\U00002145',
		"Cayleys;":                         '\U0000212D',
		"Ccaron;":                          '\U0000010C',
		"Ccedil;":                          '\U000000C7',
		"Ccirc;":                           '\U00000108',
		"Cconint;":                         '\U00002230',
		"Cdot;":                            '\U0000010A',
		"Cedilla;":                         '\U000000B8',
		"CenterDot;":                       '\U000000B7',
		"Cfr;":                             '\U0000212D',
		"Chi;":                             '\U000003A7',
		"CircleDot;":                       '\U00002299',
		"CircleMinus;":                     '\U00002296',
		"CirclePlus;":                      '\U00002295',
		"CircleTimes;":                     '\U00002297',
		"ClockwiseContourIntegral;":        '\U00002232',
		"CloseCurlyDoubleQuote;":           '\U0000201D',
		"CloseCurlyQuote;":                 '\U00002019',
		"Colon;":                           '\U00002237',
		"Colone;":                          '\U00002A74',
		"Congruent;":                       '\U00002261',
		"Conint;":                          '\U0000222F',
		"ContourIntegral;":                 '\U0000222E',
		"Copf;":                            '\U00002102',
		"Coproduct;":                       '\U00002210',
		"CounterClockwiseContourIntegral;": '\U00002233',
		"Cross;":                           '\U00002A2F',
		"Cscr;":                            '\U0001D49E',
		"Cup;":                             '\U000022D3',
		"CupCap;":                          '\U0000224D',
		"DD;":                              '\U00002145',
		"DDotrahd;":                        '\U00002911',
		"DJcy;":                            '\U00000402',
		"DScy;":                            '\U00000405',
		"DZcy;":                            '\U0000040F',
		"Dagger;":                          '\U00002021',
		"Darr;":                            '\U000021A1',
		"Dashv;":                           '\U00002AE4',
		"Dcaron;":                          '\U0000010E',
		"Dcy;":                             '\U00000414',
		"Del;":                             '\U00002207',
		"Delta;":                           '\U00000394',
		"Dfr;":                             '\U0001D507',
		"DiacriticalAcute;":                '\U000000B4',
		"DiacriticalDot;":                  '\U000002D9',
		"DiacriticalDoubleAcute;":          '\U000002DD',
		"DiacriticalGrave;":                '\U00000060',
		"DiacriticalTilde;":                '\U000002DC',
		"Diamond;":                         '\U000022C4',
		"DifferentialD;":                   '\U00002146',
		"Dopf;":                            '\U0001D53B',
		"Dot;":                             '\U000000A8',
		"DotDot;":                          '\U000020DC',
		"DotEqual;":                        '\U00002250',
		"DoubleContourIntegral;":           '\U0000222F',
		"DoubleDot;":                       '\U000000A8',
		"DoubleDownArrow;":                 '\U000021D3',
		"DoubleLeftArrow;":                 '\U000021D0',
		"DoubleLeftRightArrow;":            '\U000021D4',
		"DoubleLeftTee;":                   '\U00002AE4',
		"DoubleLongLeftArrow;":             '\U000027F8',
		"DoubleLongLeftRightArrow;":        '\U000027FA',
		"DoubleLongRightArrow;":            '\U000027F9',
		"DoubleRightArrow;":                '\U000021D2',
		"DoubleRightTee;":                  '\U000022A8',
		"DoubleUpArrow;":                   '\U000021D1',
		"DoubleUpDownArrow;":               '\U000021D5',
		"DoubleVerticalBar;":               '\U00002225',
		"DownArrow;":                       '\U00002193',
		"DownArrowBar;":                    '\U00002913',
		"DownArrowUpArrow;":                '\U000021F5',
		"DownBreve;":                       '\U00000311',
		"DownLeftRightVector;":             '\U00002950',
		"DownLeftTeeVector;":               '\U0000295E',
		"DownLeftVector;":                  '\U000021BD',
		"DownLeftVectorBar;":               '\U00002956',
		"DownRightTeeVector;":              '\U0000295F',
		"DownRightVector;":                 '\U000021C1',
		"DownRightVectorBar;":              '\U00002957',
		"DownTee;":                         '\U000022A4',
		"DownTeeArrow;":                    '\U000021A7',
		"Downarrow;":                       '\U000021D3',
		"Dscr;":                            '\U0001D49F',
		"Dstrok;":                          '\U00000110',
		"ENG;":                             '\U0000014A',
		"ETH;":                             '\U000000D0',
		"Eacute;":                          '\U000000C9',
		"Ecaron;":                          '\U0000011A',
		"Ecirc;":                           '\U000000CA',
		"Ecy;":                             '\U0000042D',
		"Edot;":                            '\U00000116',
		"Efr;":                             '\U0001D508',
		"Egrave;":                          '\U000000C8',
		"Element;":                         '\U00002208',
		"Emacr;":                           '\U00000112',
		"EmptySmallSquare;":                '\U000025FB',
		"EmptyVerySmallSquare;":            '\U000025AB',
		"Eogon;":                           '\U00000118',
		"Eopf;":                            '\U0001D53C',
		"Epsilon;":                         '\U00000395',
		"Equal;":                           '\U00002A75',
		"EqualTilde;":                      '\U00002242',
		"Equilibrium;":                     '\U000021CC',
		"Escr;":                            '\U00002130',
		"Esim;":                            '\U00002A73',
		"Eta;":                             '\U00000397',
		"Euml;":                            '\U000000CB',
		"Exists;":                          '\U00002203',
		"ExponentialE;":                    '\U00002147',
		"Fcy;":                             '\U00000424',
		"Ffr;":                             '\U0001D509',
		"FilledSmallSquare;":               '\U000025FC',
		"FilledVerySmallSquare;":           '\U000025AA',
		"Fopf;":                            '\U0001D53D',
		"ForAll;":                          '\U00002200',
		"Fouriertrf;":                      '\U00002131',
		"Fscr;":                            '\U00002131',
		"GJcy;":                            '\U00000403',
		"GT;":                              '\U0000003E',
		"Gamma;":                           '\U00000393',
		"Gammad;":                          '\U000003DC',
		"Gbreve;":                          '\U0000011E',
		"Gcedil;":                          '\U00000122',
		"Gcirc;":                           '\U0000011C',
		"Gcy;":                             '\U00000413',
		"Gdot;":                            '\U00000120',
		"Gfr;":                             '\U0001D50A',
		"Gg;":                              '\U000022D9',
		"Gopf;":                            '\U0001D53E',
		"GreaterEqual;":                    '\U00002265',
		"GreaterEqualLess;":                '\U000022DB',
		"GreaterFullEqual;":                '\U00002267',
		"GreaterGreater;":                  '\U00002AA2',
		"GreaterLess;":                     '\U00002277',
		"GreaterSlantEqual;":               '\U00002A7E',
		"GreaterTilde;":                    '\U00002273',
		"Gscr;":                            '\U0001D4A2',
		"Gt;":                              '\U0000226B',
		"HARDcy;":                          '\U0000042A',
		"Hacek;":                           '\U000002C7',
		"Hat;":                             '\U0000005E',
		"Hcirc;":                           '\U00000124',
		"Hfr;":                             '\U0000210C',
		"HilbertSpace;":                    '\U0000210B',
		"Hopf;":                            '\U0000210D',
		"HorizontalLine;":                  '\U00002500',
		"Hscr;":                            '\U0000210B',
		"Hstrok;":                          '\U00000126',
		"HumpDownHump;":                    '\U0000224E',
		"HumpEqual;":                       '\U0000224F',
		"IEcy;":                            '\U00000415',
		"IJlig;":                           '\U00000132',
		"IOcy;":                            '\U00000401',
		"Iacute;":                          '\U000000CD',
		"Icirc;":                           '\U000000CE',
		"Icy;":                             '\U00000418',
		"Idot;":                            '\U00000130',
		"Ifr;":                             '\U00002111',
		"Igrave;":                          '\U000000CC',
		"Im;":                              '\U00002111',
		"Imacr;":                           '\U0000012A',
		"ImaginaryI;":                      '\U00002148',
		"Implies;":                         '\U000021D2',
		"Int;":                             '\U0000222C',
		"Integral;":                        '\U0000222B',
		"Intersection;":                    '\U000022C2',
		"InvisibleComma;":                  '\U00002063',
		"InvisibleTimes;":                  '\U00002062',
		"Iogon;":                           '\U0000012E',
		"Iopf;":                            '\U0001D540',
		"Iota;":                            '\U00000399',
		"Iscr;":                            '\U00002110',
		"Itilde;":                          '\U00000128',
		"Iukcy;":                           '\U00000406',
		"Iuml;":                            '\U000000CF',
		"Jcirc;":                           '\U00000134',
		"Jcy;":                             '\U00000419',
		"Jfr;":                             '\U0001D50D',
		"Jopf;":                            '\U0001D541',
		"Jscr;":                            '\U0001D4A5',
		"Jsercy;":                          '\U00000408',
		"Jukcy;":                           '\U00000404',
		"KHcy;":                            '\U00000425',
		"KJcy;":                            '\U0000040C',
		"Kappa;":                           '\U0000039A',
		"Kcedil;":                          '\U00000136',
		"Kcy;":                             '\U0000041A',
		"Kfr;":                             '\U0001D50E',
		"Kopf;":                            '\U0001D542',
		"Kscr;":                            '\U0001D4A6',
		"LJcy;":                            '\U00000409',
		"LT;":                              '\U0000003C',
		"Lacute;":                          '\U00000139',
		"Lambda;":                          '\U0000039B',
		"Lang;":                            '\U000027EA',
		"Laplacetrf;":                      '\U00002112',
		"Larr;":                            '\U0000219E',
		"Lcaron;":                          '\U0000013D',
		"Lcedil;":                          '\U0000013B',
		"Lcy;":                             '\U0000041B',
		"LeftAngleBracket;":                '\U000027E8',
		"LeftArrow;":                       '\U00002190',
		"LeftArrowBar;":                    '\U000021E4',
		"LeftArrowRightArrow;":             '\U000021C6',
		"LeftCeiling;":                     '\U00002308',
		"LeftDoubleBracket;":               '\U000027E6',
		"LeftDownTeeVector;":               '\U00002961',
		"LeftDownVector;":                  '\U000021C3',
		"LeftDownVectorBar;":               '\U00002959',
		"LeftFloor;":                       '\U0000230A',
		"LeftRightArrow;":                  '\U00002194',
		"LeftRightVector;":                 '\U0000294E',
		"LeftTee;":                         '\U000022A3',
		"LeftTeeArrow;":                    '\U000021A4',
		"LeftTeeVector;":                   '\U0000295A',
		"LeftTriangle;":                    '\U000022B2',
		"LeftTriangleBar;":                 '\U000029CF',
		"LeftTriangleEqual;":               '\U000022B4',
		"LeftUpDownVector;":                '\U00002951',
		"LeftUpTeeVector;":                 '\U00002960',
		"LeftUpVector;":                    '\U000021BF',
		"LeftUpVectorBar;":                 '\U00002958',
		"LeftVector;":                      '\U000021BC',
		"LeftVectorBar;":                   '\U00002952',
		"Leftarrow;":                       '\U000021D0',
		"Leftrightarrow;":                  '\U000021D4',
		"LessEqualGreater;":                '\U000022DA',
		"LessFullEqual;":                   '\U00002266',
		"LessGreater;":                     '\U00002276',
		"LessLess;":                        '\U00002AA1',
		"LessSlantEqual;":                  '\U00002A7D',
		"LessTilde;":                       '\U00002272',
		"Lfr;":                             '\U0001D50F',
		"Ll;":                              '\U000022D8',
		"Lleftarrow;":                      '\U000021DA',
		"Lmidot;":                          '\U0000013F',
		"LongLeftArrow;":                   '\U000027F5',
		"LongLeftRightArrow;":              '\U000027F7',
		"LongRightArrow;":                  '\U000027F6',
		"Longleftarrow;":                   '\U000027F8',
		"Longleftrightarrow;":              '\U000027FA',
		"Longrightarrow;":                  '\U000027F9',
		"Lopf;":                            '\U0001D543',
		"LowerLeftArrow;":                  '\U00002199',
		"LowerRightArrow;":                 '\U00002198',
		"Lscr;":                            '\U00002112',
		"Lsh;":                             '\U000021B0',
		"Lstrok;":                          '\U00000141',
		"Lt;":                              '\U0000226A',
		"Map;":                             '\U00002905',
		"Mcy;":                             '\U0000041C',
		"MediumSpace;":                     '\U0000205F',
		"Mellintrf;":                       '\U00002133',
		"Mfr;":                             '\U0001D510',
		"MinusPlus;":                       '\U00002213',
		"Mopf;":                            '\U0001D544',
		"Mscr;":                            '\U00002133',
		"Mu;":                              '\U0000039C',
		"NJcy;":                            '\U0000040A',
		"Nacute;":                          '\U00000143',
		"Ncaron;":                          '\U00000147',
		"Ncedil;":                          '\U00000145',
		"Ncy;":                             '\U0000041D',
		"NegativeMediumSpace;":             '\U0000200B',
		"NegativeThickSpace;":              '\U0000200B',
		"NegativeThinSpace;":               '\U0000200B',
		"NegativeVeryThinSpace;":           '\U0000200B',
		"NestedGreaterGreater;":            '\U0000226B',
		"NestedLessLess;":                  '\U0000226A',
		"NewLine;":                         '\U0000000A',
		"Nfr;":                             '\U0001D511',
		"NoBreak;":                         '\U00002060',
		"NonBreakingSpace;":                '\U000000A0',
		"Nopf;":                            '\U00002115',
		"Not;":                             '\U00002AEC',
		"NotCongruent;":                    '\U00002262',
		"NotCupCap;":                       '\U0000226D',
		"NotDoubleVerticalBar;":            '\U00002226',
		"NotElement;":                      '\U00002209',
		"NotEqual;":                        '\U00002260',
		"NotExists;":                       '\U00002204',
		"NotGreater;":                      '\U0000226F',
		"NotGreaterEqual;":                 '\U00002271',
		"NotGreaterLess;":                  '\U00002279',
		"NotGreaterTilde;":                 '\U00002275',
		"NotLeftTriangle;":                 '\U000022EA',
		"NotLeftTriangleEqual;":            '\U000022EC',
		"NotLess;":                         '\U0000226E',
		"NotLessEqual;":                    '\U00002270',
		"NotLessGreater;":                  '\U00002278',
		"NotLessTilde;":                    '\U00002274',
		"NotPrecedes;":                     '\U00002280',
		"NotPrecedesSlantEqual;":           '\U000022E0',
		"NotReverseElement;":               '\U0000220C',
		"NotRightTriangle;":                '\U000022EB',
		"NotRightTriangleEqual;":           '\U000022ED',
		"NotSquareSubsetEqual;":            '\U000022E2',
		"NotSquareSupersetEqual;":          '\U000022E3',
		"NotSubsetEqual;":                  '\U00002288',
		"NotSucceeds;":                     '\U00002281',
		"NotSucceedsSlantEqual;":           '\U000022E1',
		"NotSupersetEqual;":                '\U00002289',
		"NotTilde;":                        '\U00002241',
		"NotTildeEqual;":                   '\U00002244',
		"NotTildeFullEqual;":               '\U00002247',
		"NotTildeTilde;":                   '\U00002249',
		"NotVerticalBar;":                  '\U00002224',
		"Nscr;":                            '\U0001D4A9',
		"Ntilde;":                          '\U000000D1',
		"Nu;":                              '\U0000039D',
		"OElig;":                           '\U00000152',
		"Oacute;":                          '\U000000D3',
		"Ocirc;":                           '\U000000D4',
		"Ocy;":                             '\U0000041E',
		"Odblac;":                          '\U00000150',
		"Ofr;":                             '\U0001D512',
		"Ograve;":                          '\U000000D2',
		"Omacr;":                           '\U0000014C',
		"Omega;":                           '\U000003A9',
		"Omicron;":                         '\U0000039F',
		"Oopf;":                            '\U0001D546',
		"OpenCurlyDoubleQuote;":            '\U0000201C',
		"OpenCurlyQuote;":                  '\U00002018',
		"Or;":                              '\U00002A54',
		"Oscr;":                            '\U0001D4AA',
		"Oslash;":                          '\U000000D8',
		"Otilde;":                          '\U000000D5',
		"Otimes;":                          '\U00002A37',
		"Ouml;":                            '\U000000D6',
		"OverBar;":                         '\U0000203E',
		"OverBrace;":                       '\U000023DE',
		"OverBracket;":                     '\U000023B4',
		"OverParenthesis;":                 '\U000023DC',
		"PartialD;":                        '\U00002202',
		"Pcy;":                             '\U0000041F',
		"Pfr;":                             '\U0001D513',
		"Phi;":                             '\U000003A6',
		"Pi;":                              '\U000003A0',
		"PlusMinus;":                       '\U000000B1',
		"Poincareplane;":                   '\U0000210C',
		"Popf;":                            '\U00002119',
		"Pr;":                              '\U00002ABB',
		"Precedes;":                        '\U0000227A',
		"PrecedesEqual;":                   '\U00002AAF',
		"PrecedesSlantEqual;":              '\U0000227C',
		"PrecedesTilde;":                   '\U0000227E',
		"Prime;":                           '\U00002033',
		"Product;":                         '\U0000220F',
		"Proportion;":                      '\U00002237',
		"Proportional;":                    '\U0000221D',
		"Pscr;":                            '\U0001D4AB',
		"Psi;":                             '\U000003A8',
		"QUOT;":                            '\U00000022',
		"Qfr;":                             '\U0001D514',
		"Qopf;":                            '\U0000211A',
		"Qscr;":                            '\U0001D4AC',
		"RBarr;":                           '\U00002910',
		"REG;":                             '\U000000AE',
		"Racute;":                          '\U00000154',
		"Rang;":                            '\U000027EB',
		"Rarr;":                            '\U000021A0',
		"Rarrtl;":                          '\U00002916',
		"Rcaron;":                          '\U00000158',
		"Rcedil;":                          '\U00000156',
		"Rcy;":                             '\U00000420',
		"Re;":                              '\U0000211C',
		"ReverseElement;":                  '\U0000220B',
		"ReverseEquilibrium;":              '\U000021CB',
		"ReverseUpEquilibrium;":            '\U0000296F',
		"Rfr;":                             '\U0000211C',
		"Rho;":                             '\U000003A1',
		"RightAngleBracket;":               '\U000027E9',
		"RightArrow;":                      '\U00002192',
		"RightArrowBar;":                   '\U000021E5',
		"RightArrowLeftArrow;":             '\U000021C4',
		"RightCeiling;":                    '\U00002309',
		"RightDoubleBracket;":              '\U000027E7',
		"RightDownTeeVector;":              '\U0000295D',
		"RightDownVector;":                 '\U000021C2',
		"RightDownVectorBar;":              '\U00002955',
		"RightFloor;":                      '\U0000230B',
		"RightTee;":                        '\U000022A2',
		"RightTeeArrow;":                   '\U000021A6',
		"RightTeeVector;":                  '\U0000295B',
		"RightTriangle;":                   '\U000022B3',
		"RightTriangleBar;":                '\U000029D0',
		"RightTriangleEqual;":              '\U000022B5',
		"RightUpDownVector;":               '\U0000294F',
		"RightUpTeeVector;":                '\U0000295C',
		"RightUpVector;":                   '\U000021BE',
		"RightUpVectorBar;":                '\U00002954',
		"RightVector;":                     '\U000021C0',
		"RightVectorBar;":                  '\U00002953',
		"Rightarrow;":                      '\U000021D2',
		"Ropf;":                            '\U0000211D',
		"RoundImplies;":                    '\U00002970',
		"Rrightarrow;":                     '\U000021DB',
		"Rscr;":                            '\U0000211B',
		"Rsh;":                             '\U000021B1',
		"RuleDelayed;":                     '\U000029F4',
		"SHCHcy;":                          '\U00000429',
		"SHcy;":                            '\U00000428',
		"SOFTcy;":                          '\U0000042C',
		"Sacute;":                          '\U0000015A',
		"Sc;":                              '\U00002ABC',
		"Scaron;":                          '\U00000160',
		"Scedil;":                          '\U0000015E',
		"Scirc;":                           '\U0000015C',
		"Scy;":                             '\U00000421',
		"Sfr;":                             '\U0001D516',
		"ShortDownArrow;":                  '\U00002193',
		"ShortLeftArrow;":                  '\U00002190',
		"ShortRightArrow;":                 '\U00002192',
		"ShortUpArrow;":                    '\U00002191',
		"Sigma;":                           '\U000003A3',
		"SmallCircle;":                     '\U00002218',
		"Sopf;":                            '\U0001D54A',
		"Sqrt;":                            '\U0000221A',
		"Square;":                          '\U000025A1',
		"SquareIntersection;":              '\U00002293',
		"SquareSubset;":                    '\U0000228F',
		"SquareSubsetEqual;":               '\U00002291',
		"SquareSuperset;":                  '\U00002290',
		"SquareSupersetEqual;":             '\U00002292',
		"SquareUnion;":                     '\U00002294',
		"Sscr;":                            '\U0001D4AE',
		"Star;":                            '\U000022C6',
		"Sub;":                             '\U000022D0',
		"Subset;":                          '\U000022D0',
		"SubsetEqual;":                     '\U00002286',
		"Succeeds;":                        '\U0000227B',
		"SucceedsEqual;":                   '\U00002AB0',
		"SucceedsSlantEqual;":              '\U0000227D',
		"SucceedsTilde;":                   '\U0000227F',
		"SuchThat;":                        '\U0000220B',
		"Sum;":                             '\U00002211',
		"Sup;":                             '\U000022D1',
		"Superset;":                        '\U00002283',
		"SupersetEqual;":                   '\U00002287',
		"Supset;":                          '\U000022D1',
		"THORN;":                           '\U000000DE',
		"TRADE;":                           '\U00002122',
		"TSHcy;":                           '\U0000040B',
		"TScy;":                            '\U00000426',
		"Tab;":                             '\U00000009',
		"Tau;":                             '\U000003A4',
		"Tcaron;":                          '\U00000164',
		"Tcedil;":                          '\U00000162',
		"Tcy;":                             '\U00000422',
		"Tfr;":                             '\U0001D517',
		"Therefore;":                       '\U00002234',
		"Theta;":                           '\U00000398',
		"ThinSpace;":                       '\U00002009',
		"Tilde;":                           '\U0000223C',
		"TildeEqual;":                      '\U00002243',
		"TildeFullEqual;":                  '\U00002245',
		"TildeTilde;":                      '\U00002248',
		"Topf;":                            '\U0001D54B',
		"TripleDot;":                       '\U000020DB',
		"Tscr;":                            '\U0001D4AF',
		"Tstrok;":                          '\U00000166',
		"Uacute;":                          '\U000000DA',
		"Uarr;":                            '\U0000219F',
		"Uarrocir;":                        '\U00002949',
		"Ubrcy;":                           '\U0000040E',
		"Ubreve;":                          '\U0000016C',
		"Ucirc;":                           '\U000000DB',
		"Ucy;":                             '\U00000423',
		"Udblac;":                          '\U00000170',
		"Ufr;":                             '\U0001D518',
		"Ugrave;":                          '\U000000D9',
		"Umacr;":                           '\U0000016A',
		"UnderBar;":                        '\U0000005F',
		"UnderBrace;":                      '\U000023DF',
		"UnderBracket;":                    '\U000023B5',
		"UnderParenthesis;":                '\U000023DD',
		"Union;":                           '\U000022C3',
		"UnionPlus;":                       '\U0000228E',
		"Uogon;":                           '\U00000172',
		"Uopf;":                            '\U0001D54C',
		"UpArrow;":                         '\U00002191',
		"UpArrowBar;":                      '\U00002912',
		"UpArrowDownArrow;":                '\U000021C5',
		"UpDownArrow;":                     '\U00002195',
		"UpEquilibrium;":                   '\U0000296E',
		"UpTee;":                           '\U000022A5',
		"UpTeeArrow;":                      '\U000021A5',
		"Uparrow;":                         '\U000021D1',
		"Updownarrow;":                     '\U000021D5',
		"UpperLeftArrow;":                  '\U00002196',
		"UpperRightArrow;":                 '\U00002197',
		"Upsi;":                            '\U000003D2',
		"Upsilon;":                         '\U000003A5',
		"Uring;":                           '\U0000016E',
		"Uscr;":                            '\U0001D4B0',
		"Utilde;":                          '\U00000168',
		"Uuml;":                            '\U000000DC',
		"VDash;":                           '\U000022AB',
		"Vbar;":                            '\U00002AEB',
		"Vcy;":                             '\U00000412',
		"Vdash;":                           '\U000022A9',
		"Vdashl;":                          '\U00002AE6',
		"Vee;":                             '\U000022C1',
		"Verbar;":                          '\U00002016',
		"Vert;":                            '\U00002016',
		"VerticalBar;":                     '\U00002223',
		"VerticalLine;":                    '\U0000007C',
		"VerticalSeparator;":               '\U00002758',
		"VerticalTilde;":                   '\U00002240',
		"VeryThinSpace;":                   '\U0000200A',
		"Vfr;":                             '\U0001D519',
		"Vopf;":                            '\U0001D54D',
		"Vscr;":                            '\U0001D4B1',
		"Vvdash;":                          '\U000022AA',
		"Wcirc;":                           '\U00000174',
		"Wedge;":                           '\U000022C0',
		"Wfr;":                             '\U0001D51A',
		"Wopf;":                            '\U0001D54E',
		"Wscr;":                            '\U0001D4B2',
		"Xfr;":                             '\U0001D51B',
		"Xi;":                              '\U0000039E',
		"Xopf;":                            '\U0001D54F',
		"Xscr;":                            '\U0001D4B3',
		"YAcy;":                            '\U0000042F',
		"YIcy;":                            '\U00000407',
		"YUcy;":                            '\U0000042E',
		"Yacute;":                          '\U000000DD',
		"Ycirc;":                           '\U00000176',
		"Ycy;":                             '\U0000042B',
		"Yfr;":                             '\U0001D51C',
		"Yopf;":                            '\U0001D550',
		"Yscr;":                            '\U0001D4B4',
		"Yuml;":                            '\U00000178',
		"ZHcy;":                            '\U00000416',
		"Zacute;":                          '\U00000179',
		"Zcaron;":                          '\U0000017D',
		"Zcy;":                             '\U00000417',
		"Zdot;":                            '\U0000017B',
		"ZeroWidthSpace;":                  '\U0000200B',
		"Zeta;":                            '\U00000396',
		"Zfr;":                             '\U00002128',
		"Zopf;":                            '\U00002124',
		"Zscr;":                            '\U0001D4B5',
		"aacute;":                          '\U000000E1',
		"abreve;":                          '\U00000103',
		"ac;":                              '\U0000223E',
		"acd;":                             '\U0000223F',
		"acirc;":                           '\U000000E2',
		"acute;":                           '\U000000B4',
		"acy;":                             '\U00000430',
		"aelig;":                           '\U000000E6',
		"af;":                              '\U00002061',
		"afr;":                             '\U0001D51E',
		"agrave;":                          '\U000000E0',
		"alefsym;":                         '\U00002135',
		"aleph;":                           '\U00002135',
		"alpha;":                           '\U000003B1',
		"amacr;":                           '\U00000101',
		"amalg;":                           '\U00002A3F',
		"amp;":                             '\U00000026',
		"and;":                             '\U00002227',
		"andand;":                          '\U00002A55',
		"andd;":                            '\U00002A5C',
		"andslope;":                        '\U00002A58',
		"andv;":                            '\U00002A5A',
		"ang;":                             '\U00002220',
		"ange;":                            '\U000029A4',
		"angle;":                           '\U00002220',
		"angmsd;":                          '\U00002221',
		"angmsdaa;":                        '\U000029A8',
		"angmsdab;":                        '\U000029A9',
		"angmsdac;":                        '\U000029AA',
		"angmsdad;":                        '\U000029AB',
		"angmsdae;":                        '\U000029AC',
		"angmsdaf;":                        '\U000029AD',
		"angmsdag;":                        '\U000029AE',
		"angmsdah;":                        '\U000029AF',
		"angrt;":                           '\U0000221F',
		"angrtvb;":                         '\U000022B
"""




```