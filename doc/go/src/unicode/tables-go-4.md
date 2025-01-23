Response:
My thought process for answering the request goes like this:

1. **Understand the Goal:** The user wants to know the functionality of the provided Go code snippet, which appears to be part of the `unicode` package in Go. They specifically ask for a summary of the functionality, examples, and potential pitfalls for users. This is the fifth part of a seven-part series, so the final part will be a comprehensive summary.

2. **Initial Code Scan and High-Level Interpretation:** I quickly scanned the code and identified the following key elements:
    * **Constant Definitions:** A large number of constants (e.g., `Chakma`, `Cham`, `Cherokee`, etc.) are being defined and assigned to variables like `_Chakma`, `_Cham`, `_Cherokee`. The names strongly suggest Unicode scripts.
    * **`Properties` Map:** A map called `Properties` is being initialized. The keys are strings like "ASCII_Hex_Digit", "Bidi_Control", etc., which are suggestive of Unicode properties. The values are of type `*RangeTable`.
    * **`RangeTable` Variables:** Several variables like `_ASCII_Hex_Digit`, `_Bidi_Control`, `_Dash`, etc., are declared and initialized with `&RangeTable{...}`. These seem to represent tables of Unicode code point ranges.

3. **Formulate Hypotheses:** Based on the initial scan, I formed the following hypotheses:
    * **Script Enumeration:** The constants likely represent an enumeration of Unicode scripts.
    * **Property Mapping:** The `Properties` map likely maps Unicode property names to tables containing the code points that possess those properties.
    * **`RangeTable` Structure:**  The `RangeTable` likely stores ranges of Unicode code points (potentially with optimizations for different code point sizes using `R16` and `R32`).

4. **Connect to Go's `unicode` Package:** I recalled that Go's `unicode` package is indeed responsible for handling Unicode character properties and classifications. This reinforces my hypotheses.

5. **Functionality Breakdown (Step-by-Step Reasoning):**

    * **Script Constants:** The code explicitly defines constants for various Unicode scripts. This allows Go programs to easily refer to and potentially work with characters from specific scripts.
    * **Unicode Property Tables:** The `Properties` map is the core functionality here. It provides a way to access pre-computed tables for common Unicode properties. This avoids having to recalculate these properties every time they're needed, improving performance. Each entry in the map associates a well-known Unicode property name with its corresponding `RangeTable`.
    * **`RangeTable` Details:** The `RangeTable` structure is used to efficiently store ranges of Unicode code points. The separation into `R16` (for code points representable in 16 bits) and `R32` (for code points requiring 32 bits) is a memory optimization. The `LatinOffset` field is less immediately obvious but likely serves an optimization related to ASCII characters or a common subset.

6. **Code Example Construction:** To illustrate the functionality, I focused on the `unicode.Properties` map and how it can be used. I picked the "Dash" property as an example because it's relatively common and easy to understand. I wrote Go code that:
    * Imports the `unicode` package.
    * Iterates through a string.
    * Checks if each rune (Unicode code point) in the string belongs to the "Dash" property using the `unicode.Is()` function and the table obtained from `unicode.Properties["Dash"]`.
    * Prints whether each rune is a dash character or not.

7. **Input and Output for the Example:** I provided a simple input string containing a hyphen, an em dash, and the letter 'a'. I then predicted the output, clearly showing which characters would be identified as belonging to the "Dash" property.

8. **Identify Potential User Errors:**  I considered common mistakes developers might make when using this functionality:
    * **Incorrect Property Names:** Typos or using non-existent property names when accessing the `Properties` map would lead to nil pointers and runtime errors.
    * **Misunderstanding Property Definitions:**  Users might not fully grasp the exact definition of a Unicode property (e.g., the subtle differences between "Dash" and "Hyphen").

9. **Summarize the Functionality (Part 5):**  For this specific part, I focused on the core idea of the code: providing a structured way to access Unicode character sets based on script and property.

10. **Consider the "Part X of Y" Context:** I kept in mind that this is part of a larger explanation. Therefore, I avoided going into excessive detail that might be covered in other parts, focusing on the specific code provided. The final summary in part 7 will likely combine the functionalities of all the snippets.

11. **Language and Formatting:**  I used clear and concise Chinese, as requested. I also used appropriate formatting (code blocks, bolding) to make the answer easy to read and understand.

By following these steps, I aimed to provide a comprehensive and accurate explanation of the provided Go code snippet, addressing all aspects of the user's request.
## 功能列举与代码推理 (第5部分)

这段Go代码实现了 `unicode` 包中关于 **Unicode 字符集和属性表的定义**。具体来说，它做了以下几件事：

1. **定义了大量表示 Unicode 脚本的常量:**  例如 `Chakma`, `Cham`, `Cherokee` 等。每个常量都赋值为一个以下划线开头的变量 (`_Chakma`, `_Cham`, `_Cherokee`)。 这些变量很可能在其他部分代码中被初始化为包含该脚本下所有字符的 `RangeTable`。
2. **定义了一个 `Properties` 变量，它是一个 `map[string]*RangeTable`:** 这个 map 将 Unicode 的属性名称（字符串）映射到对应的 `RangeTable` 指针。`RangeTable` 结构体（未在此段代码中定义，但在 `unicode` 包中存在）很可能用于高效地存储字符范围。
3. **定义了许多以下划线开头的 `RangeTable` 类型的变量:** 例如 `_ASCII_Hex_Digit`, `_Bidi_Control`, `_Dash` 等。  每个变量都被初始化为一个 `RangeTable` 字面量，其中包含了特定 Unicode 属性对应的字符范围。例如，`_ASCII_Hex_Digit` 包含了 ASCII 十六进制数字的字符范围。

**推理：这是 Go 语言 `unicode` 包中用于查询字符属性的功能实现。**

`unicode` 包是 Go 语言标准库中用于处理 Unicode 字符的核心包。这段代码定义了各种 Unicode 字符集（基于脚本）和属性，并使用 `RangeTable` 数据结构来高效存储这些信息。通过 `Properties` map，我们可以根据属性名称快速查找到对应的字符范围表。

**Go 代码举例说明:**

假设在 `unicode/tables.go` 的其他部分，以下划线开头的变量（如 `_Han`）被初始化为包含所有汉字的 `RangeTable`，`_ASCII_Hex_Digit` 被初始化为包含 ASCII 十六进制数字的 `RangeTable`。

```go
package main

import (
	"fmt"
	"unicode"
)

func main() {
	// 假设 '你' 是一个汉字，'A' 是一个 ASCII 十六进制数字，'!' 不是
	runeHan := '你'
	runeA := 'A'
	runeBang := '!'

	// 检查字符是否属于 "Han" 脚本
	if unicode.Is(unicode.Han, runeHan) {
		fmt.Printf("%c 是汉字\n", runeHan) // 输出：你 是汉字
	} else {
		fmt.Printf("%c 不是汉字\n", runeHan)
	}

	if unicode.Is(unicode.Han, runeA) {
		fmt.Printf("%c 是汉字\n", runeA)
	} else {
		fmt.Printf("%c 不是汉字\n", runeA) // 输出：A 不是汉字
	}

	// 检查字符是否拥有 "ASCII_Hex_Digit" 属性
	if unicode.Is(unicode.Properties["ASCII_Hex_Digit"], runeA) {
		fmt.Printf("%c 是 ASCII 十六进制数字\n", runeA) // 输出：A 是 ASCII 十六进制数字
	} else {
		fmt.Printf("%c 不是 ASCII 十六进制数字\n", runeA)
	}

	if unicode.Is(unicode.Properties["ASCII_Hex_Digit"], runeBang) {
		fmt.Printf("%c 是 ASCII 十六进制数字\n", runeBang)
	} else {
		fmt.Printf("%c 不是 ASCII 十六进制数字\n", runeBang) // 输出：! 不是 ASCII 十六进制数字
	}
}
```

**假设的输入与输出:**

上述代码示例没有命令行参数。其输出取决于硬编码的字符。输出已在代码注释中给出。

**使用者易犯错的点:**

1. **属性名称拼写错误:**  访问 `unicode.Properties` map 时，如果属性名称拼写错误，会导致返回 `nil` 指针，在后续使用时会引发 panic。

   ```go
   // 错误示例：属性名拼写错误
   if unicode.Is(unicode.Properties["ASCI_Hex_Digit"], 'A') { // "ASCII" 拼写成了 "ASCI"
       // ...
   }
   ```
   这段代码在运行时会因为访问 `nil` 指针而崩溃。

2. **混淆脚本和属性:**  使用者可能不清楚某些字符是属于特定的脚本还是拥有特定的属性。例如，一个字符可能既属于 `Latin` 脚本，也同时拥有 `Uppercase` 属性。

   ```go
   runeB := 'B'
   if unicode.Is(unicode.Latin, runeB) {
       fmt.Println("B 属于 Latin 脚本") // 输出：B 属于 Latin 脚本
   }
   if unicode.Is(unicode.Properties["Uppercase"], runeB) {
       fmt.Println("B 拥有 Uppercase 属性") // 输出：B 拥有 Uppercase 属性
   }
   ```
   使用者需要理解脚本是基于文字系统的分类，而属性是字符的各种特征。

**功能归纳 (第5部分):**

这段代码的核心功能是 **定义了 Go 语言 `unicode` 包用于表示和访问 Unicode 字符集（基于脚本）和字符属性的数据结构和常量。** 它声明了大量的 Unicode 脚本常量，并提供了一个 `Properties` map，用于将 Unicode 属性名称映射到包含相应字符范围的 `RangeTable`。  这是 `unicode` 包实现字符分类和属性查询的基础。

### 提示词
```
这是路径为go/src/unicode/tables.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```go
// Chakma is the set of Unicode characters in script Chakma.
	Cham                   = _Cham                   // Cham is the set of Unicode characters in script Cham.
	Cherokee               = _Cherokee               // Cherokee is the set of Unicode characters in script Cherokee.
	Chorasmian             = _Chorasmian             // Chorasmian is the set of Unicode characters in script Chorasmian.
	Common                 = _Common                 // Common is the set of Unicode characters in script Common.
	Coptic                 = _Coptic                 // Coptic is the set of Unicode characters in script Coptic.
	Cuneiform              = _Cuneiform              // Cuneiform is the set of Unicode characters in script Cuneiform.
	Cypriot                = _Cypriot                // Cypriot is the set of Unicode characters in script Cypriot.
	Cypro_Minoan           = _Cypro_Minoan           // Cypro_Minoan is the set of Unicode characters in script Cypro_Minoan.
	Cyrillic               = _Cyrillic               // Cyrillic is the set of Unicode characters in script Cyrillic.
	Deseret                = _Deseret                // Deseret is the set of Unicode characters in script Deseret.
	Devanagari             = _Devanagari             // Devanagari is the set of Unicode characters in script Devanagari.
	Dives_Akuru            = _Dives_Akuru            // Dives_Akuru is the set of Unicode characters in script Dives_Akuru.
	Dogra                  = _Dogra                  // Dogra is the set of Unicode characters in script Dogra.
	Duployan               = _Duployan               // Duployan is the set of Unicode characters in script Duployan.
	Egyptian_Hieroglyphs   = _Egyptian_Hieroglyphs   // Egyptian_Hieroglyphs is the set of Unicode characters in script Egyptian_Hieroglyphs.
	Elbasan                = _Elbasan                // Elbasan is the set of Unicode characters in script Elbasan.
	Elymaic                = _Elymaic                // Elymaic is the set of Unicode characters in script Elymaic.
	Ethiopic               = _Ethiopic               // Ethiopic is the set of Unicode characters in script Ethiopic.
	Georgian               = _Georgian               // Georgian is the set of Unicode characters in script Georgian.
	Glagolitic             = _Glagolitic             // Glagolitic is the set of Unicode characters in script Glagolitic.
	Gothic                 = _Gothic                 // Gothic is the set of Unicode characters in script Gothic.
	Grantha                = _Grantha                // Grantha is the set of Unicode characters in script Grantha.
	Greek                  = _Greek                  // Greek is the set of Unicode characters in script Greek.
	Gujarati               = _Gujarati               // Gujarati is the set of Unicode characters in script Gujarati.
	Gunjala_Gondi          = _Gunjala_Gondi          // Gunjala_Gondi is the set of Unicode characters in script Gunjala_Gondi.
	Gurmukhi               = _Gurmukhi               // Gurmukhi is the set of Unicode characters in script Gurmukhi.
	Han                    = _Han                    // Han is the set of Unicode characters in script Han.
	Hangul                 = _Hangul                 // Hangul is the set of Unicode characters in script Hangul.
	Hanifi_Rohingya        = _Hanifi_Rohingya        // Hanifi_Rohingya is the set of Unicode characters in script Hanifi_Rohingya.
	Hanunoo                = _Hanunoo                // Hanunoo is the set of Unicode characters in script Hanunoo.
	Hatran                 = _Hatran                 // Hatran is the set of Unicode characters in script Hatran.
	Hebrew                 = _Hebrew                 // Hebrew is the set of Unicode characters in script Hebrew.
	Hiragana               = _Hiragana               // Hiragana is the set of Unicode characters in script Hiragana.
	Imperial_Aramaic       = _Imperial_Aramaic       // Imperial_Aramaic is the set of Unicode characters in script Imperial_Aramaic.
	Inherited              = _Inherited              // Inherited is the set of Unicode characters in script Inherited.
	Inscriptional_Pahlavi  = _Inscriptional_Pahlavi  // Inscriptional_Pahlavi is the set of Unicode characters in script Inscriptional_Pahlavi.
	Inscriptional_Parthian = _Inscriptional_Parthian // Inscriptional_Parthian is the set of Unicode characters in script Inscriptional_Parthian.
	Javanese               = _Javanese               // Javanese is the set of Unicode characters in script Javanese.
	Kaithi                 = _Kaithi                 // Kaithi is the set of Unicode characters in script Kaithi.
	Kannada                = _Kannada                // Kannada is the set of Unicode characters in script Kannada.
	Katakana               = _Katakana               // Katakana is the set of Unicode characters in script Katakana.
	Kawi                   = _Kawi                   // Kawi is the set of Unicode characters in script Kawi.
	Kayah_Li               = _Kayah_Li               // Kayah_Li is the set of Unicode characters in script Kayah_Li.
	Kharoshthi             = _Kharoshthi             // Kharoshthi is the set of Unicode characters in script Kharoshthi.
	Khitan_Small_Script    = _Khitan_Small_Script    // Khitan_Small_Script is the set of Unicode characters in script Khitan_Small_Script.
	Khmer                  = _Khmer                  // Khmer is the set of Unicode characters in script Khmer.
	Khojki                 = _Khojki                 // Khojki is the set of Unicode characters in script Khojki.
	Khudawadi              = _Khudawadi              // Khudawadi is the set of Unicode characters in script Khudawadi.
	Lao                    = _Lao                    // Lao is the set of Unicode characters in script Lao.
	Latin                  = _Latin                  // Latin is the set of Unicode characters in script Latin.
	Lepcha                 = _Lepcha                 // Lepcha is the set of Unicode characters in script Lepcha.
	Limbu                  = _Limbu                  // Limbu is the set of Unicode characters in script Limbu.
	Linear_A               = _Linear_A               // Linear_A is the set of Unicode characters in script Linear_A.
	Linear_B               = _Linear_B               // Linear_B is the set of Unicode characters in script Linear_B.
	Lisu                   = _Lisu                   // Lisu is the set of Unicode characters in script Lisu.
	Lycian                 = _Lycian                 // Lycian is the set of Unicode characters in script Lycian.
	Lydian                 = _Lydian                 // Lydian is the set of Unicode characters in script Lydian.
	Mahajani               = _Mahajani               // Mahajani is the set of Unicode characters in script Mahajani.
	Makasar                = _Makasar                // Makasar is the set of Unicode characters in script Makasar.
	Malayalam              = _Malayalam              // Malayalam is the set of Unicode characters in script Malayalam.
	Mandaic                = _Mandaic                // Mandaic is the set of Unicode characters in script Mandaic.
	Manichaean             = _Manichaean             // Manichaean is the set of Unicode characters in script Manichaean.
	Marchen                = _Marchen                // Marchen is the set of Unicode characters in script Marchen.
	Masaram_Gondi          = _Masaram_Gondi          // Masaram_Gondi is the set of Unicode characters in script Masaram_Gondi.
	Medefaidrin            = _Medefaidrin            // Medefaidrin is the set of Unicode characters in script Medefaidrin.
	Meetei_Mayek           = _Meetei_Mayek           // Meetei_Mayek is the set of Unicode characters in script Meetei_Mayek.
	Mende_Kikakui          = _Mende_Kikakui          // Mende_Kikakui is the set of Unicode characters in script Mende_Kikakui.
	Meroitic_Cursive       = _Meroitic_Cursive       // Meroitic_Cursive is the set of Unicode characters in script Meroitic_Cursive.
	Meroitic_Hieroglyphs   = _Meroitic_Hieroglyphs   // Meroitic_Hieroglyphs is the set of Unicode characters in script Meroitic_Hieroglyphs.
	Miao                   = _Miao                   // Miao is the set of Unicode characters in script Miao.
	Modi                   = _Modi                   // Modi is the set of Unicode characters in script Modi.
	Mongolian              = _Mongolian              // Mongolian is the set of Unicode characters in script Mongolian.
	Mro                    = _Mro                    // Mro is the set of Unicode characters in script Mro.
	Multani                = _Multani                // Multani is the set of Unicode characters in script Multani.
	Myanmar                = _Myanmar                // Myanmar is the set of Unicode characters in script Myanmar.
	Nabataean              = _Nabataean              // Nabataean is the set of Unicode characters in script Nabataean.
	Nag_Mundari            = _Nag_Mundari            // Nag_Mundari is the set of Unicode characters in script Nag_Mundari.
	Nandinagari            = _Nandinagari            // Nandinagari is the set of Unicode characters in script Nandinagari.
	New_Tai_Lue            = _New_Tai_Lue            // New_Tai_Lue is the set of Unicode characters in script New_Tai_Lue.
	Newa                   = _Newa                   // Newa is the set of Unicode characters in script Newa.
	Nko                    = _Nko                    // Nko is the set of Unicode characters in script Nko.
	Nushu                  = _Nushu                  // Nushu is the set of Unicode characters in script Nushu.
	Nyiakeng_Puachue_Hmong = _Nyiakeng_Puachue_Hmong // Nyiakeng_Puachue_Hmong is the set of Unicode characters in script Nyiakeng_Puachue_Hmong.
	Ogham                  = _Ogham                  // Ogham is the set of Unicode characters in script Ogham.
	Ol_Chiki               = _Ol_Chiki               // Ol_Chiki is the set of Unicode characters in script Ol_Chiki.
	Old_Hungarian          = _Old_Hungarian          // Old_Hungarian is the set of Unicode characters in script Old_Hungarian.
	Old_Italic             = _Old_Italic             // Old_Italic is the set of Unicode characters in script Old_Italic.
	Old_North_Arabian      = _Old_North_Arabian      // Old_North_Arabian is the set of Unicode characters in script Old_North_Arabian.
	Old_Permic             = _Old_Permic             // Old_Permic is the set of Unicode characters in script Old_Permic.
	Old_Persian            = _Old_Persian            // Old_Persian is the set of Unicode characters in script Old_Persian.
	Old_Sogdian            = _Old_Sogdian            // Old_Sogdian is the set of Unicode characters in script Old_Sogdian.
	Old_South_Arabian      = _Old_South_Arabian      // Old_South_Arabian is the set of Unicode characters in script Old_South_Arabian.
	Old_Turkic             = _Old_Turkic             // Old_Turkic is the set of Unicode characters in script Old_Turkic.
	Old_Uyghur             = _Old_Uyghur             // Old_Uyghur is the set of Unicode characters in script Old_Uyghur.
	Oriya                  = _Oriya                  // Oriya is the set of Unicode characters in script Oriya.
	Osage                  = _Osage                  // Osage is the set of Unicode characters in script Osage.
	Osmanya                = _Osmanya                // Osmanya is the set of Unicode characters in script Osmanya.
	Pahawh_Hmong           = _Pahawh_Hmong           // Pahawh_Hmong is the set of Unicode characters in script Pahawh_Hmong.
	Palmyrene              = _Palmyrene              // Palmyrene is the set of Unicode characters in script Palmyrene.
	Pau_Cin_Hau            = _Pau_Cin_Hau            // Pau_Cin_Hau is the set of Unicode characters in script Pau_Cin_Hau.
	Phags_Pa               = _Phags_Pa               // Phags_Pa is the set of Unicode characters in script Phags_Pa.
	Phoenician             = _Phoenician             // Phoenician is the set of Unicode characters in script Phoenician.
	Psalter_Pahlavi        = _Psalter_Pahlavi        // Psalter_Pahlavi is the set of Unicode characters in script Psalter_Pahlavi.
	Rejang                 = _Rejang                 // Rejang is the set of Unicode characters in script Rejang.
	Runic                  = _Runic                  // Runic is the set of Unicode characters in script Runic.
	Samaritan              = _Samaritan              // Samaritan is the set of Unicode characters in script Samaritan.
	Saurashtra             = _Saurashtra             // Saurashtra is the set of Unicode characters in script Saurashtra.
	Sharada                = _Sharada                // Sharada is the set of Unicode characters in script Sharada.
	Shavian                = _Shavian                // Shavian is the set of Unicode characters in script Shavian.
	Siddham                = _Siddham                // Siddham is the set of Unicode characters in script Siddham.
	SignWriting            = _SignWriting            // SignWriting is the set of Unicode characters in script SignWriting.
	Sinhala                = _Sinhala                // Sinhala is the set of Unicode characters in script Sinhala.
	Sogdian                = _Sogdian                // Sogdian is the set of Unicode characters in script Sogdian.
	Sora_Sompeng           = _Sora_Sompeng           // Sora_Sompeng is the set of Unicode characters in script Sora_Sompeng.
	Soyombo                = _Soyombo                // Soyombo is the set of Unicode characters in script Soyombo.
	Sundanese              = _Sundanese              // Sundanese is the set of Unicode characters in script Sundanese.
	Syloti_Nagri           = _Syloti_Nagri           // Syloti_Nagri is the set of Unicode characters in script Syloti_Nagri.
	Syriac                 = _Syriac                 // Syriac is the set of Unicode characters in script Syriac.
	Tagalog                = _Tagalog                // Tagalog is the set of Unicode characters in script Tagalog.
	Tagbanwa               = _Tagbanwa               // Tagbanwa is the set of Unicode characters in script Tagbanwa.
	Tai_Le                 = _Tai_Le                 // Tai_Le is the set of Unicode characters in script Tai_Le.
	Tai_Tham               = _Tai_Tham               // Tai_Tham is the set of Unicode characters in script Tai_Tham.
	Tai_Viet               = _Tai_Viet               // Tai_Viet is the set of Unicode characters in script Tai_Viet.
	Takri                  = _Takri                  // Takri is the set of Unicode characters in script Takri.
	Tamil                  = _Tamil                  // Tamil is the set of Unicode characters in script Tamil.
	Tangsa                 = _Tangsa                 // Tangsa is the set of Unicode characters in script Tangsa.
	Tangut                 = _Tangut                 // Tangut is the set of Unicode characters in script Tangut.
	Telugu                 = _Telugu                 // Telugu is the set of Unicode characters in script Telugu.
	Thaana                 = _Thaana                 // Thaana is the set of Unicode characters in script Thaana.
	Thai                   = _Thai                   // Thai is the set of Unicode characters in script Thai.
	Tibetan                = _Tibetan                // Tibetan is the set of Unicode characters in script Tibetan.
	Tifinagh               = _Tifinagh               // Tifinagh is the set of Unicode characters in script Tifinagh.
	Tirhuta                = _Tirhuta                // Tirhuta is the set of Unicode characters in script Tirhuta.
	Toto                   = _Toto                   // Toto is the set of Unicode characters in script Toto.
	Ugaritic               = _Ugaritic               // Ugaritic is the set of Unicode characters in script Ugaritic.
	Vai                    = _Vai                    // Vai is the set of Unicode characters in script Vai.
	Vithkuqi               = _Vithkuqi               // Vithkuqi is the set of Unicode characters in script Vithkuqi.
	Wancho                 = _Wancho                 // Wancho is the set of Unicode characters in script Wancho.
	Warang_Citi            = _Warang_Citi            // Warang_Citi is the set of Unicode characters in script Warang_Citi.
	Yezidi                 = _Yezidi                 // Yezidi is the set of Unicode characters in script Yezidi.
	Yi                     = _Yi                     // Yi is the set of Unicode characters in script Yi.
	Zanabazar_Square       = _Zanabazar_Square       // Zanabazar_Square is the set of Unicode characters in script Zanabazar_Square.
)

// Properties is the set of Unicode property tables.
var Properties = map[string]*RangeTable{
	"ASCII_Hex_Digit":                    ASCII_Hex_Digit,
	"Bidi_Control":                       Bidi_Control,
	"Dash":                               Dash,
	"Deprecated":                         Deprecated,
	"Diacritic":                          Diacritic,
	"Extender":                           Extender,
	"Hex_Digit":                          Hex_Digit,
	"Hyphen":                             Hyphen,
	"IDS_Binary_Operator":                IDS_Binary_Operator,
	"IDS_Trinary_Operator":               IDS_Trinary_Operator,
	"Ideographic":                        Ideographic,
	"Join_Control":                       Join_Control,
	"Logical_Order_Exception":            Logical_Order_Exception,
	"Noncharacter_Code_Point":            Noncharacter_Code_Point,
	"Other_Alphabetic":                   Other_Alphabetic,
	"Other_Default_Ignorable_Code_Point": Other_Default_Ignorable_Code_Point,
	"Other_Grapheme_Extend":              Other_Grapheme_Extend,
	"Other_ID_Continue":                  Other_ID_Continue,
	"Other_ID_Start":                     Other_ID_Start,
	"Other_Lowercase":                    Other_Lowercase,
	"Other_Math":                         Other_Math,
	"Other_Uppercase":                    Other_Uppercase,
	"Pattern_Syntax":                     Pattern_Syntax,
	"Pattern_White_Space":                Pattern_White_Space,
	"Prepended_Concatenation_Mark":       Prepended_Concatenation_Mark,
	"Quotation_Mark":                     Quotation_Mark,
	"Radical":                            Radical,
	"Regional_Indicator":                 Regional_Indicator,
	"Sentence_Terminal":                  Sentence_Terminal,
	"STerm":                              Sentence_Terminal,
	"Soft_Dotted":                        Soft_Dotted,
	"Terminal_Punctuation":               Terminal_Punctuation,
	"Unified_Ideograph":                  Unified_Ideograph,
	"Variation_Selector":                 Variation_Selector,
	"White_Space":                        White_Space,
}

var _ASCII_Hex_Digit = &RangeTable{
	R16: []Range16{
		{0x0030, 0x0039, 1},
		{0x0041, 0x0046, 1},
		{0x0061, 0x0066, 1},
	},
	LatinOffset: 3,
}

var _Bidi_Control = &RangeTable{
	R16: []Range16{
		{0x061c, 0x200e, 6642},
		{0x200f, 0x202a, 27},
		{0x202b, 0x202e, 1},
		{0x2066, 0x2069, 1},
	},
}

var _Dash = &RangeTable{
	R16: []Range16{
		{0x002d, 0x058a, 1373},
		{0x05be, 0x1400, 3650},
		{0x1806, 0x2010, 2058},
		{0x2011, 0x2015, 1},
		{0x2053, 0x207b, 40},
		{0x208b, 0x2212, 391},
		{0x2e17, 0x2e1a, 3},
		{0x2e3a, 0x2e3b, 1},
		{0x2e40, 0x2e5d, 29},
		{0x301c, 0x3030, 20},
		{0x30a0, 0xfe31, 52625},
		{0xfe32, 0xfe58, 38},
		{0xfe63, 0xff0d, 170},
	},
	R32: []Range32{
		{0x10ead, 0x10ead, 1},
	},
}

var _Deprecated = &RangeTable{
	R16: []Range16{
		{0x0149, 0x0673, 1322},
		{0x0f77, 0x0f79, 2},
		{0x17a3, 0x17a4, 1},
		{0x206a, 0x206f, 1},
		{0x2329, 0x232a, 1},
	},
	R32: []Range32{
		{0xe0001, 0xe0001, 1},
	},
}

var _Diacritic = &RangeTable{
	R16: []Range16{
		{0x005e, 0x0060, 2},
		{0x00a8, 0x00af, 7},
		{0x00b4, 0x00b7, 3},
		{0x00b8, 0x02b0, 504},
		{0x02b1, 0x034e, 1},
		{0x0350, 0x0357, 1},
		{0x035d, 0x0362, 1},
		{0x0374, 0x0375, 1},
		{0x037a, 0x0384, 10},
		{0x0385, 0x0483, 254},
		{0x0484, 0x0487, 1},
		{0x0559, 0x0591, 56},
		{0x0592, 0x05a1, 1},
		{0x05a3, 0x05bd, 1},
		{0x05bf, 0x05c1, 2},
		{0x05c2, 0x05c4, 2},
		{0x064b, 0x0652, 1},
		{0x0657, 0x0658, 1},
		{0x06df, 0x06e0, 1},
		{0x06e5, 0x06e6, 1},
		{0x06ea, 0x06ec, 1},
		{0x0730, 0x074a, 1},
		{0x07a6, 0x07b0, 1},
		{0x07eb, 0x07f5, 1},
		{0x0818, 0x0819, 1},
		{0x0898, 0x089f, 1},
		{0x08c9, 0x08d2, 1},
		{0x08e3, 0x08fe, 1},
		{0x093c, 0x094d, 17},
		{0x0951, 0x0954, 1},
		{0x0971, 0x09bc, 75},
		{0x09cd, 0x0a3c, 111},
		{0x0a4d, 0x0abc, 111},
		{0x0acd, 0x0afd, 48},
		{0x0afe, 0x0aff, 1},
		{0x0b3c, 0x0b4d, 17},
		{0x0b55, 0x0bcd, 120},
		{0x0c3c, 0x0c4d, 17},
		{0x0cbc, 0x0ccd, 17},
		{0x0d3b, 0x0d3c, 1},
		{0x0d4d, 0x0e47, 125},
		{0x0e48, 0x0e4c, 1},
		{0x0e4e, 0x0eba, 108},
		{0x0ec8, 0x0ecc, 1},
		{0x0f18, 0x0f19, 1},
		{0x0f35, 0x0f39, 2},
		{0x0f3e, 0x0f3f, 1},
		{0x0f82, 0x0f84, 1},
		{0x0f86, 0x0f87, 1},
		{0x0fc6, 0x1037, 113},
		{0x1039, 0x103a, 1},
		{0x1063, 0x1064, 1},
		{0x1069, 0x106d, 1},
		{0x1087, 0x108d, 1},
		{0x108f, 0x109a, 11},
		{0x109b, 0x135d, 706},
		{0x135e, 0x135f, 1},
		{0x1714, 0x1715, 1},
		{0x17c9, 0x17d3, 1},
		{0x17dd, 0x1939, 348},
		{0x193a, 0x193b, 1},
		{0x1a75, 0x1a7c, 1},
		{0x1a7f, 0x1ab0, 49},
		{0x1ab1, 0x1abe, 1},
		{0x1ac1, 0x1acb, 1},
		{0x1b34, 0x1b44, 16},
		{0x1b6b, 0x1b73, 1},
		{0x1baa, 0x1bab, 1},
		{0x1c36, 0x1c37, 1},
		{0x1c78, 0x1c7d, 1},
		{0x1cd0, 0x1ce8, 1},
		{0x1ced, 0x1cf4, 7},
		{0x1cf7, 0x1cf9, 1},
		{0x1d2c, 0x1d6a, 1},
		{0x1dc4, 0x1dcf, 1},
		{0x1df5, 0x1dff, 1},
		{0x1fbd, 0x1fbf, 2},
		{0x1fc0, 0x1fc1, 1},
		{0x1fcd, 0x1fcf, 1},
		{0x1fdd, 0x1fdf, 1},
		{0x1fed, 0x1fef, 1},
		{0x1ffd, 0x1ffe, 1},
		{0x2cef, 0x2cf1, 1},
		{0x2e2f, 0x302a, 507},
		{0x302b, 0x302f, 1},
		{0x3099, 0x309c, 1},
		{0x30fc, 0xa66f, 30067},
		{0xa67c, 0xa67d, 1},
		{0xa67f, 0xa69c, 29},
		{0xa69d, 0xa6f0, 83},
		{0xa6f1, 0xa700, 15},
		{0xa701, 0xa721, 1},
		{0xa788, 0xa78a, 1},
		{0xa7f8, 0xa7f9, 1},
		{0xa8c4, 0xa8e0, 28},
		{0xa8e1, 0xa8f1, 1},
		{0xa92b, 0xa92e, 1},
		{0xa953, 0xa9b3, 96},
		{0xa9c0, 0xa9e5, 37},
		{0xaa7b, 0xaa7d, 1},
		{0xaabf, 0xaac2, 1},
		{0xaaf6, 0xab5b, 101},
		{0xab5c, 0xab5f, 1},
		{0xab69, 0xab6b, 1},
		{0xabec, 0xabed, 1},
		{0xfb1e, 0xfe20, 770},
		{0xfe21, 0xfe2f, 1},
		{0xff3e, 0xff40, 2},
		{0xff70, 0xff9e, 46},
		{0xff9f, 0xffe3, 68},
	},
	R32: []Range32{
		{0x102e0, 0x10780, 1184},
		{0x10781, 0x10785, 1},
		{0x10787, 0x107b0, 1},
		{0x107b2, 0x107ba, 1},
		{0x10ae5, 0x10ae6, 1},
		{0x10d22, 0x10d27, 1},
		{0x10efd, 0x10eff, 1},
		{0x10f46, 0x10f50, 1},
		{0x10f82, 0x10f85, 1},
		{0x11046, 0x11070, 42},
		{0x110b9, 0x110ba, 1},
		{0x11133, 0x11134, 1},
		{0x11173, 0x111c0, 77},
		{0x111ca, 0x111cc, 1},
		{0x11235, 0x11236, 1},
		{0x112e9, 0x112ea, 1},
		{0x1133c, 0x1134d, 17},
		{0x11366, 0x1136c, 1},
		{0x11370, 0x11374, 1},
		{0x11442, 0x11446, 4},
		{0x114c2, 0x114c3, 1},
		{0x115bf, 0x115c0, 1},
		{0x1163f, 0x116b6, 119},
		{0x116b7, 0x1172b, 116},
		{0x11839, 0x1183a, 1},
		{0x1193d, 0x1193e, 1},
		{0x11943, 0x119e0, 157},
		{0x11a34, 0x11a47, 19},
		{0x11a99, 0x11c3f, 422},
		{0x11d42, 0x11d44, 2},
		{0x11d45, 0x11d97, 82},
		{0x13447, 0x13455, 1},
		{0x16af0, 0x16af4, 1},
		{0x16b30, 0x16b36, 1},
		{0x16f8f, 0x16f9f, 1},
		{0x16ff0, 0x16ff1, 1},
		{0x1aff0, 0x1aff3, 1},
		{0x1aff5, 0x1affb, 1},
		{0x1affd, 0x1affe, 1},
		{0x1cf00, 0x1cf2d, 1},
		{0x1cf30, 0x1cf46, 1},
		{0x1d167, 0x1d169, 1},
		{0x1d16d, 0x1d172, 1},
		{0x1d17b, 0x1d182, 1},
		{0x1d185, 0x1d18b, 1},
		{0x1d1aa, 0x1d1ad, 1},
		{0x1e030, 0x1e06d, 1},
		{0x1e130, 0x1e136, 1},
		{0x1e2ae, 0x1e2ec, 62},
		{0x1e2ed, 0x1e2ef, 1},
		{0x1e8d0, 0x1e8d6, 1},
		{0x1e944, 0x1e946, 1},
		{0x1e948, 0x1e94a, 1},
	},
	LatinOffset: 3,
}

var _Extender = &RangeTable{
	R16: []Range16{
		{0x00b7, 0x02d0, 537},
		{0x02d1, 0x0640, 879},
		{0x07fa, 0x0b55, 859},
		{0x0e46, 0x0ec6, 128},
		{0x180a, 0x1843, 57},
		{0x1aa7, 0x1c36, 399},
		{0x1c7b, 0x3005, 5002},
		{0x3031, 0x3035, 1},
		{0x309d, 0x309e, 1},
		{0x30fc, 0x30fe, 1},
		{0xa015, 0xa60c, 1527},
		{0xa9cf, 0xa9e6, 23},
		{0xaa70, 0xaadd, 109},
		{0xaaf3, 0xaaf4, 1},
		{0xff70, 0xff70, 1},
	},
	R32: []Range32{
		{0x10781, 0x10782, 1},
		{0x1135d, 0x115c6, 617},
		{0x115c7, 0x115c8, 1},
		{0x11a98, 0x16b42, 20650},
		{0x16b43, 0x16fe0, 1181},
		{0x16fe1, 0x16fe3, 2},
		{0x1e13c, 0x1e13d, 1},
		{0x1e944, 0x1e946, 1},
	},
}

var _Hex_Digit = &RangeTable{
	R16: []Range16{
		{0x0030, 0x0039, 1},
		{0x0041, 0x0046, 1},
		{0x0061, 0x0066, 1},
		{0xff10, 0xff19, 1},
		{0xff21, 0xff26, 1},
		{0xff41, 0xff46, 1},
	},
	LatinOffset: 3,
}

var _Hyphen = &RangeTable{
	R16: []Range16{
		{0x002d, 0x00ad, 128},
		{0x058a, 0x1806, 4732},
		{0x2010, 0x2011, 1},
		{0x2e17, 0x30fb, 740},
		{0xfe63, 0xff0d, 170},
		{0xff65, 0xff65, 1},
	},
	LatinOffset: 1,
}

var _IDS_Binary_Operator = &RangeTable{
	R16: []Range16{
		{0x2ff0, 0x2ff1, 1},
		{0x2ff4, 0x2ffb, 1},
	},
}

var _IDS_Trinary_Operator = &RangeTable{
	R16: []Range16{
		{0x2ff2, 0x2ff3, 1},
	},
}

var _Ideographic = &RangeTable{
	R16: []Range16{
		{0x3006, 0x3007, 1},
		{0x3021, 0x3029, 1},
		{0x3038, 0x303a, 1},
		{0x3400, 0x4dbf, 1},
		{0x4e00, 0x9fff, 1},
		{0xf900, 0xfa6d, 1},
		{0xfa70, 0xfad9, 1},
	},
	R32: []Range32{
		{0x16fe4, 0x17000, 28},
		{0x17001, 0x187f7, 1},
		{0x18800, 0x18cd5, 1},
		{0x18d00, 0x18d08, 1},
		{0x1b170, 0x1b2fb, 1},
		{0x20000, 0x2a6df, 1},
		{0x2a700, 0x2b739, 1},
		{0x2b740, 0x2b81d, 1},
		{0x2b820, 0x2cea1, 1},
		{0x2ceb0, 0x2ebe0, 1},
		{0x2f800, 0x2fa1d, 1},
		{0x30000, 0x3134a, 1},
		{0x31350, 0x323af, 1},
	},
}

var _Join_Control = &RangeTable{
	R16: []Range16{
		{0x200c, 0x200d, 1},
	},
}

var _Logical_Order_Exception = &RangeTable{
	R16: []Range16{
		{0x0e40, 0x0e44, 1},
		{0x0ec0, 0x0ec4, 1},
		{0x19b5, 0x19b7, 1},
		{0x19ba, 0xaab5, 37115},
		{0xaab6, 0xaab9, 3},
		{0xaabb, 0xaabc, 1},
	},
}

var _Noncharacter_Code_Point = &RangeTable{
	R16: []Range16{
		{0xfdd0, 0xfdef, 1},
		{0xfffe, 0xffff, 1},
	},
	R32: []Range32{
		{0x1fffe, 0x1ffff, 1},
		{0x2fffe, 0x2ffff, 1},
		{0x3fffe, 0x3ffff, 1},
		{0x4fffe, 0x4ffff, 1},
		{0x5fffe, 0x5ffff, 1},
		{0x6fffe, 0x6ffff, 1},
		{0x7fffe, 0x7ffff, 1},
		{0x8fffe, 0x8ffff, 1},
		{0x9fffe, 0x9ffff, 1},
		{0xafffe, 0xaffff, 1},
		{0xbfffe, 0xbffff, 1},
		{0xcfffe, 0xcffff, 1},
		{0xdfffe, 0xdffff, 1},
		{0xefffe, 0xeffff, 1},
		{0xffffe, 0xfffff, 1},
		{0x10fffe, 0x10ffff, 1},
	},
}

var _Other_Alphabetic = &RangeTable{
	R16: []Range16{
		{0x0345, 0x05b0, 619},
		{0x05b1, 0x05bd, 1},
		{0x05bf, 0x05c1, 2},
		{0x05c2, 0x05c4, 2},
		{0x05c5, 0x05c7, 2},
		{0x0610, 0x061a, 1},
		{0x064b, 0x0657, 1},
		{0x0659, 0x065f, 1},
		{0x0670, 0x06d6, 102},
		{0x06d7, 0x06dc, 1},
		{0x06e1, 0x06e4, 1},
		{0x06e7, 0x06e8, 1},
		{0x06ed, 0x0711, 36},
		{0x0730, 0x073f, 1},
		{0x07a6, 0x07b0, 1},
		{0x0816, 0x0817, 1},
		{0x081b, 0x0823, 1},
		{0x0825, 0x0827, 1},
		{0x0829, 0x082c, 1},
		{0x08d4, 0x08df, 1},
		{0x08e3, 0x08e9, 1},
		{0x08f0, 0x0903, 1},
		{0x093a, 0x093b, 1},
		{0x093e, 0x094c, 1},
		{0x094e, 0x094f, 1},
		{0x0955, 0x0957, 1},
		{0x0962, 0x0963, 1},
		{0x0981, 0x0983, 1},
		{0x09be, 0x09c4, 1},
		{0x09c7, 0x09c8, 1},
		{0x09cb, 0x09cc, 1},
		{0x09d7, 0x09e2, 11},
		{0x09e3, 0x0a01, 30},
		{0x0a02, 0x0a03, 1},
		{0x0a3e, 0x0a42, 1},
		{0x0a47, 0x0a48, 1},
		{0x0a4b, 0x0a4c, 1},
		{0x0a51, 0x0a70, 31},
		{0x0a71, 0x0a75, 4},
		{0x0a81, 0x0a83, 1},
		{0x0abe, 0x0ac5, 1},
		{0x0ac7, 0x0ac9, 1},
		{0x0acb, 0x0acc, 1},
		{0x0ae2, 0x0ae3, 1},
		{0x0afa, 0x0afc, 1},
		{0x0b01, 0x0b03, 1},
		{0x0b3e, 0x0b44, 1},
		{0x0b47, 0x0b48, 1},
		{0x0b4b, 0x0b4c, 1},
		{0x0b56, 0x0b57, 1},
		{0x0b62, 0x0b63, 1},
		{0x0b82, 0x0bbe, 60},
		{0x0bbf, 0x0bc2, 1},
		{0x0bc6, 0x0bc8, 1},
		{0x0bca, 0x0bcc, 1},
		{0x0bd7, 0x0c00, 41},
		{0x0c01, 0x0c04, 1},
		{0x0c3e, 0x0c44, 1},
		{0x0c46, 0x0c48, 1},
		{0x0c4a, 0x0c4c, 1},
		{0x0c55, 0x0c56, 1},
		{0x0c62, 0x0c63, 1},
		{0x0c81, 0x0c83, 1},
		{0x0cbe, 0x0cc4, 1},
		{0x0cc6, 0x0cc8, 1},
		{0x0cca, 0x0ccc, 1},
		{0x0cd5, 0x0cd6, 1},
		{0x0ce2, 0x0ce3, 1},
		{0x0cf3, 0x0d00, 13},
		{0x0d01, 0x0d03, 1},
		{0x0d3e, 0x0d44, 1},
		{0x0d46, 0x0d48, 1},
		{0x0d4a, 0x0d4c, 1},
		{0x0d57, 0x0d62, 11},
		{0x0d63, 0x0d81, 30},
		{0x0d82, 0x0d83, 1},
		{0x0dcf, 0x0dd4, 1},
		{0x0dd6, 0x0dd8, 2},
		{0x0dd9, 0x0ddf, 1},
		{0x0df2, 0x0df3, 1},
		{0x0e31, 0x0e34, 3},
		{0x0e35, 0x0e3a, 1},
		{0x0e4d, 0x0eb1, 100},
		{0x0eb4, 0x0eb9, 1},
		{0x0ebb, 0x0ebc, 1},
		{0x0ecd, 0x0f71, 164},
		{0x0f72, 0x0f83, 1},
		{0x0f8d, 0x0f97, 1},
		{0x0f99, 0x0fbc, 1},
		{0x102b, 0x1036, 1},
		{0x1038, 0x103b, 3},
		{0x103c, 0x103e, 1},
		{0x1056, 0x1059, 1},
		{0x105e, 0x1060, 1},
		{0x1062, 0x1064, 1},
		{0x1067, 0x106d, 1},
		{0x1071, 0x1074, 1},
		{0x1082, 0x108d, 1},
		{0x108f, 0x109a, 11},
		{0x109b, 0x109d, 1},
		{0x1712, 0x1713, 1},
		{0x1732, 0x1733, 1},
		{0x1752, 0x1753, 1},
		{0x1772, 0x1773, 1},
		{0x17b6, 0x17c8, 1},
		{0x1885, 0x1886, 1},
		{0x18a9, 0x1920, 119},
		{0x1921, 0x192b, 1},
		{0x1930, 0x1938, 1},
		{0x1a17, 0x1a1b, 1},
		{0x1a55, 0x1a5e, 1},
		{0x1a61, 0x1a74, 1},
		{0x1abf, 0x1ac0, 1},
		{0x1acc, 0x1ace, 1},
		{0x1b00, 0x1b04, 1},
		{0x1b35, 0x1b43, 1},
		{0x1b80, 0x1b82, 1},
		{0x1ba1, 0x1ba9, 1},
		{0x1bac, 0x1bad, 1},
		{0x1be7, 0x1bf1, 1},
		{0x1c24, 0x1c36, 1},
		{0x1de7, 0x1df4, 1},
		{0x24b6, 0x24e9, 1},
		{0x2de0, 0x2dff, 1},
		{0xa674, 0xa67b, 1},
		{0xa69e, 0xa69f, 1},
		{0xa802, 0xa80b, 9},
		{0xa823, 0xa827, 1},
		{0xa880, 0xa881, 1},
		{0xa8b4, 0xa8c3, 1},
		{0xa8c5, 0xa8ff, 58},
		{0xa926, 0xa92a, 1},
		{0xa947, 0xa952, 1},
		{0xa980, 0xa983, 1},
		{0xa9b4, 0xa9bf, 1},
		{0xa9e5, 0xaa29, 68},
		{0xaa2a, 0xaa36, 1},
		{0xaa43, 0xaa4c, 9},
		{0xaa4d, 0xaa7b, 46},
		{0xaa7c, 0xaa7d, 1},
		{0xaab0, 0xaab2, 2},
		{0xaab3, 0xaab4, 1},
		{0xaab7, 0xaab8, 1},
		{0xaabe, 0xaaeb, 45},
		{0xaaec, 0xaaef, 1},
		{0xaaf5, 0xabe3, 238},
		{0xabe4, 0xabea, 1},
		{0xfb1e, 0xfb1e, 1},
	},
	R32: []Range32{
		{0x10376, 0x1037a, 1},
		{0x10a01, 0x10a03, 1},
		{0x10a05, 0x10a06, 1},
		{0x10a0c, 0x10a0f, 1},
		{0x10d24, 0x10d27, 1},
		{0x10eab, 0x10eac, 1},
		{0x11000, 0x11002, 1},
		{0x11038, 0x11045, 1},
		{0x11073, 0x11074, 1},
		{0x11080, 0x11082, 1},
		{0x110b0, 0x110b8, 1},
		{0x110c2, 0x11100, 62},
		{0x11101, 0x11102, 1},
		{0x11127, 0x11132, 1},
		{0x11145, 0x11146, 1},
		{0x11180, 0x11182, 1},
		{0x111b3, 0x111bf, 1},
		{0x111ce, 0x111cf, 1},
		{0x1122c, 0x11234, 1},
		{0x11237, 0x1123e, 7},
		{0x11241, 0x112df, 158},
		{0x112e0, 0x112e8, 1},
		{0x11300, 0x11303, 1},
		{0x1133e, 0x11344, 1},
		{0x11347, 0x11348, 1},
		{0x1134b, 0x1134c, 1},
		{0x11357, 0x11362, 11},
		{0x11363, 0x11435, 210},
		{0x11436, 0x11441, 1},
		{0x11443, 0x11445, 1},
		{0x114b0, 0x114c1, 1},
		{0x115af, 0x115b5, 1},
		{0x115b8, 0x115be, 1},
		{0x115dc, 0x115dd, 1},
		{0x11630, 0x1163e, 1},
		{0x11640, 0x116ab, 107},
		{0x116ac, 0x116b5, 1},
		{0x1171d, 0x1172a, 1},
		{0x1182c, 0x11838, 1},
		{0x11930, 0x11935, 1},
		{0x11937, 0x11938, 1},
		{0x1193b, 0x1193c, 1},
		{0x11940, 0x11942, 2},
		{0x119d1, 0x119d7, 1},
		{0x119da, 0x119df, 1},
		{0x119e4, 0x11a01, 29},
		{0x11a02, 0x11a0a, 1},
		{0x11a35, 0x11a39, 1},
		{0x11a3b, 0x11a3e, 1},
		{0x11a51, 0x11a5b, 1},
		{0x11a8a, 0x11a97, 1},
		{0x11c2f, 0x11c36, 1},
		{0x11c38, 0x11c3e, 1},
		{0x11c92, 0x11ca7, 1},
		{0x11ca9, 0x11cb6, 1},
		{0x11d31, 0x11d36, 1},
		{0x11d3a, 0x11d3c, 2},
		{0x11d3d, 0x11d3f, 2},
		{0x11d40, 0x11d41, 1},
		{0x11d43, 0x11d47, 4},
		{0x11d8a, 0x11d8e, 1},
		{0x11d90, 0x11d91, 1},
		{0x11d93, 0x11d96, 1},
		{0x11ef3, 0x11ef6, 1},
		{0x11f00, 0x11f01, 1},
		{0x11f03, 0x11f34, 49},
		{0x11f35, 0x11f3a, 1},
		{0x11f3e, 0x11f40, 1},
		{0x16f4f, 0x16f51, 2},
		{0x16f52, 0x16f87, 1},
		{0x16f8f, 0x16f92, 1},
		{0x16ff0, 0x16ff1, 1},
		{0x1bc9e, 0x1e000, 9058},
		{0x1e001, 0x1e006, 1},
		{0x1e008, 0x1e018, 1},
		{0x1e01b, 0x1e021, 1},
		{0x1e023, 0x1e024, 1},
		{0x1e026, 0x1e02a, 1},
		{0x1e08f, 0x1e947, 2232},
		{0x1f130, 0x1f149, 1},
		{0x1f150, 0x1f169, 1},
		{0x1f170, 0x1f189, 1},
	},
}

var _Other_Default_Ignorable_Code_Point = &RangeTable{
	R16: []Range16{
		{0x034f, 0x115f, 3600},
		{0x1160, 0x17b4, 1620},
		{0x17b5, 0x2065, 2224},
		{0x3164, 0xffa0, 52796},
		{0xfff0, 0xfff8, 1},
	},
	R32: []Range32{
		{0xe0000, 0xe0002, 2},
		{0xe0003, 0xe001f, 1},
		{0xe0080, 0xe00ff, 1},
		{0xe01f0, 0xe0fff, 1},
	},
}

var _Other_Grapheme_Extend = &RangeTable{
	R16: []Range16{
		{0x09be, 0x09d7, 25},
		{0x0b3e, 0x0b57, 25},
		{0x0bbe, 0x0bd7, 25},
		{0x0cc2, 0x0cd5, 19},
		{0x0cd6, 0x0d3e, 104},
		{0x0d57, 0x0dcf, 120},
		{0x0ddf, 0x1b35, 3414},
		{0x200c, 0x302e, 4130},
		{0x302f, 0xff9e, 53103},
		{0xff9f, 0xff9f, 1},
	},
	R32: []Range32{
		{0x1133e, 0x11357, 25},
		{0x114b0, 0x114bd, 13},
		{0x115af, 0x11930, 897},
		{0x1d165, 0x1d16e, 9},
		{0x1d16f, 0x1d172, 1},
		{0xe0020, 0xe007f, 1},
	},
}

var _Other_ID_Continue = &RangeTable{
	R16: []Range16{
		{0x00b7, 0x0387, 720},
		{0x1369, 0x1371, 1},
		{0x19da, 0x19da, 1},
	},
}

var _Other_ID_Start =
```