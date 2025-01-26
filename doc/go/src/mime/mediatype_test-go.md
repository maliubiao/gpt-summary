Response:
Let's break down the thought process for analyzing the given Go code snippet.

**1. Initial Understanding and Context:**

* **File Path:** The path `go/src/mime/mediatype_test.go` immediately tells us this is a test file within the `mime` package of the Go standard library. The `_test.go` suffix is a standard Go convention for test files.
* **Package Declaration:** `package mime` confirms it's testing functionality within the `mime` package.
* **Imports:** The imports `maps`, `strings`, and `testing` are typical for Go test files. `testing` is essential for writing tests, `strings` likely used for string manipulation in tests, and `maps` is probably used for comparing maps (parameter lists).

**2. Identifying the Core Functionality Under Test:**

* **Function Names Starting with `Test`:** Go's testing framework relies on functions starting with `Test` to identify test cases. Scanning the code, we see `TestConsumeToken`, `TestConsumeValue`, `TestConsumeMediaParam`, and `TestParseMediaType`, `TestParseMediaTypeBogus`, `TestFormatMediaType`. These names directly suggest the functions being tested: `consumeToken`, `consumeValue`, `consumeMediaParam`, `ParseMediaType`, and `FormatMediaType`.

**3. Analyzing Individual Test Functions:**

* **`TestConsumeToken`:**  The name suggests it tests a function that extracts a "token" from a string. The test cases show examples of what constitutes a token (alphanumeric characters). The assertions check if the extracted token and the remaining part of the string are correct.
* **`TestConsumeValue`:** Similar to `TestConsumeToken`, but it seems to handle quoted values as well, including escaped quotes and backslashes. This suggests it's testing how to extract a "value" which can be either a simple token or a quoted string.
* **`TestConsumeMediaParam`:** This tests the extraction of "media parameters," which are key-value pairs in the format `key=value`. The test cases demonstrate handling of spaces, semicolons, and quoted values within parameters.
* **`TestParseMediaType`:**  This appears to be the central test. The test cases are more complex, involving full media type strings like `form-data; name="foo"`. The assertions check if the media type and its parameters are parsed correctly. The examples include various edge cases, like different quoting styles, case sensitivity, and RFC 2231 encoding for filenames.
* **`TestParseMediaTypeBogus`:** This tests the error handling of `ParseMediaType` when given invalid input. The assertions check for the expected error messages.
* **`TestFormatMediaType`:**  This tests the reverse operation: taking a media type and its parameters and formatting them into a string. The test cases ensure correct quoting, encoding (like UTF-8 for non-ASCII characters), and ordering of parameters.

**4. Inferring the Purpose of the Underlying Functions:**

Based on the tests:

* **`consumeToken(s string)`:**  Likely takes a string `s` and returns the first token and the rest of the string. A token seems to be a sequence of non-space characters.
* **`consumeValue(s string)`:**  Likely takes a string `s` and returns the first value (either a token or a quoted string, handling escapes) and the rest of the string.
* **`consumeMediaParam(s string)`:** Likely takes a string `s` (starting with a semicolon or space-semicolon) and returns the parameter name, its value, and the rest of the string.
* **`ParseMediaType(s string)`:** This is the main function. It takes a media type string and returns the main type/subtype, a map of parameters, and an error.
* **`FormatMediaType(typ string, params map[string]string)`:** Takes a media type string and a map of parameters and returns the formatted media type string.

**5. Go Feature Identification:**

The code is clearly testing the parsing and formatting of MIME media types. This is a fundamental part of handling content types in HTTP and other protocols.

**6. Code Examples (Based on Inference):**

Constructing examples involves imagining how the tested functions would be used. For `ParseMediaType`, we can use common media type strings. For the `consume` functions, we can use substrings of media type strings.

**7. Command-Line Arguments:**

The test code itself doesn't directly process command-line arguments. However, when running the tests using `go test`, the Go testing framework might accept arguments. This is a general property of Go testing, not specific to this file.

**8. Common Mistakes:**

By looking at the `badMediaTypeTests`, we can identify common errors users might make, like missing semicolons, unescaped characters in quoted strings, or duplicate parameters.

**9. Structuring the Answer:**

The final step is to organize the findings into a clear and comprehensive answer, using headings and bullet points for readability. It's important to address all parts of the prompt: functionality, Go feature, code examples, command-line arguments (even if it's just to say it's not directly involved), and potential mistakes.

**Self-Correction/Refinement during the process:**

* Initially, I might have just said "string parsing functions."  However, by looking closer at the parameter names (`mediaParam`), and the context of the `mime` package, I refined it to "MIME media type parsing."
*  Seeing the RFC 2231 examples in `TestParseMediaType` highlighted the importance of that standard in handling internationalized filenames.
* I noticed the `maps.Equal` function, indicating that comparing maps of parameters is a crucial part of the testing.
* I made sure to differentiate between what the *test code* does and the functionality of the *underlying package*. The test code doesn't directly handle HTTP requests, for instance, but the `mime` package is used in that context.
这个Go语言实现文件 `go/src/mime/mediatype_test.go` 是 `mime` 标准库包的一部分，专门用于测试与 MIME 媒体类型（也称为 Content-Type）处理相关的功能。

**它的主要功能是：**

1. **测试 `consumeToken` 函数:**  测试从字符串开头消费（提取）一个 token 的功能。Token 是指不包含空格的连续字符序列。
2. **测试 `consumeValue` 函数:** 测试从字符串开头消费一个 value 的功能。Value 可以是一个 token，也可以是被双引号包围的字符串，并且能够处理转义字符。
3. **测试 `consumeMediaParam` 函数:** 测试从字符串开头消费一个媒体类型参数的功能。媒体类型参数通常以 `;` 分隔，格式为 `key=value`。
4. **测试 `ParseMediaType` 函数:** 测试解析一个完整的媒体类型字符串的功能。该函数需要能够识别媒体类型的主类型和子类型，并解析出所有的参数及其对应的值。它还需要处理 RFC 2231 中定义的编码参数 (例如 `filename*=utf-8''...`)。
5. **测试 `FormatMediaType` 函数:** 测试将媒体类型和参数组合格式化成一个符合 MIME 规范的字符串。

**它是什么go语言功能的实现？**

这个文件是 Go 标准库 `mime` 包中关于 **MIME 媒体类型解析和格式化** 功能的测试代码。MIME 媒体类型在 HTTP 协议、电子邮件等领域中被广泛使用，用于标识资源的类型。

**Go代码举例说明:**

假设 `ParseMediaType` 函数的实现能够解析媒体类型字符串并返回类型（type）、参数（parameters）和一个错误。

```go
package main

import (
	"fmt"
	"mime"
)

func main() {
	mediaTypeStr := "text/html; charset=utf-8"
	mediaType, params, err := mime.ParseMediaType(mediaTypeStr)
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}
	fmt.Println("媒体类型:", mediaType)
	fmt.Println("参数:", params)

	// 假设 FormatMediaType 的实现是将类型和参数格式化成字符串
	formattedMediaType := mime.FormatMediaType("image/jpeg", map[string]string{"quality": "80"})
	fmt.Println("格式化后的媒体类型:", formattedMediaType)
}
```

**假设的输入与输出 (针对 `ParseMediaType`)：**

**输入:** `"application/json; charset=UTF-8"`
**输出:**
```
媒体类型: application/json
参数: map[charset:UTF-8]
```

**输入:** `"multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW"`
**输出:**
```
媒体类型: multipart/form-data
参数: map[boundary:----WebKitFormBoundary7MA4YWxkTrZu0gW]
```

**输入:** `"image/svg+xml; title*=utf-8'zh-CN'%E6%B5%8B%E8%AF%95"`
**输出:**
```
媒体类型: image/svg+xml
参数: map[title:测试]
```

**命令行参数的具体处理:**

这个测试文件本身不涉及命令行参数的具体处理。Go 语言的测试是通过 `go test` 命令来运行的。你可以使用 `go test` 命令来执行 `mediatype_test.go` 中的测试用例。

例如，在包含 `go/src/mime/mediatype_test.go` 文件的目录下运行以下命令：

```bash
go test
```

Go 测试框架会自动找到并执行该文件中的所有以 `Test` 开头的函数。你可以使用一些 `go test` 的选项，例如 `-v` 可以显示更详细的测试输出，`-run` 可以指定运行特定的测试用例。

**使用者易犯错的点：**

1. **媒体类型字符串格式不正确:**  例如，缺少分号分隔参数，或者参数格式错误（例如 `key value` 而不是 `key=value`）。

   **错误示例:** `"text/html charset=utf-8"`  (缺少分号)

2. **引号使用不当:**  如果 value 中包含空格或特殊字符，应该用双引号括起来。忘记使用引号或者引号没有正确配对会导致解析错误。

   **错误示例:** `"text/plain; filename=my file.txt"` (文件名包含空格，应该用引号括起来)
   **正确示例:** `"text/plain; filename=\"my file.txt\""`

3. **RFC 2231 编码参数理解不足:**  对于包含非 ASCII 字符的文件名或其他参数，需要使用 `*=utf-8''...` 这样的格式进行编码。直接在参数值中使用非 ASCII 字符可能导致解析问题。

   **错误示例:** `"attachment; filename=中文文件名.txt"`
   **正确示例:** `"attachment; filename*=utf-8''%E4%B8%AD%E6%96%87%E6%96%87%E4%BB%B6%E5%90%8D.txt"`

4. **大小写敏感性:** 虽然媒体类型的主类型和子类型在比较时通常不区分大小写（例如 `"text/html"` 和 `"TEXT/HTML"` 应该被认为是相同的），但参数名通常是大小写不敏感的。不过，`FormatMediaType` 生成的字符串通常会使用小写。

总而言之，`go/src/mime/mediatype_test.go` 这个文件详细地测试了 Go 语言 `mime` 包中处理 MIME 媒体类型字符串的各种场景，包括解析、格式化以及对特殊编码的处理。理解这些测试用例可以帮助我们更好地理解和使用 Go 语言的 MIME 处理功能，并避免一些常见的错误。

Prompt: 
```
这是路径为go/src/mime/mediatype_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package mime

import (
	"maps"
	"strings"
	"testing"
)

func TestConsumeToken(t *testing.T) {
	tests := [...][3]string{
		{"foo bar", "foo", " bar"},
		{"bar", "bar", ""},
		{"", "", ""},
		{" foo", "", " foo"},
	}
	for _, test := range tests {
		token, rest := consumeToken(test[0])
		expectedToken := test[1]
		expectedRest := test[2]
		if token != expectedToken {
			t.Errorf("expected to consume token '%s', not '%s' from '%s'",
				expectedToken, token, test[0])
		} else if rest != expectedRest {
			t.Errorf("expected to have left '%s', not '%s' after reading token '%s' from '%s'",
				expectedRest, rest, token, test[0])
		}
	}
}

func TestConsumeValue(t *testing.T) {
	tests := [...][3]string{
		{"foo bar", "foo", " bar"},
		{"bar", "bar", ""},
		{" bar ", "", " bar "},
		{`"My value"end`, "My value", "end"},
		{`"My value" end`, "My value", " end"},
		{`"\\" rest`, "\\", " rest"},
		{`"My \" value"end`, "My \" value", "end"},
		{`"\" rest`, "", `"\" rest`},
		{`"C:\dev\go\robots.txt"`, `C:\dev\go\robots.txt`, ""},
		{`"C:\新建文件夹\中文第二次测试.mp4"`, `C:\新建文件夹\中文第二次测试.mp4`, ""},
	}
	for _, test := range tests {
		value, rest := consumeValue(test[0])
		expectedValue := test[1]
		expectedRest := test[2]
		if value != expectedValue {
			t.Errorf("expected to consume value [%s], not [%s] from [%s]",
				expectedValue, value, test[0])
		} else if rest != expectedRest {
			t.Errorf("expected to have left [%s], not [%s] after reading value [%s] from [%s]",
				expectedRest, rest, value, test[0])
		}
	}
}

func TestConsumeMediaParam(t *testing.T) {
	tests := [...][4]string{
		{" ; foo=bar", "foo", "bar", ""},
		{"; foo=bar", "foo", "bar", ""},
		{";foo=bar", "foo", "bar", ""},
		{";FOO=bar", "foo", "bar", ""},
		{`;foo="bar"`, "foo", "bar", ""},
		{`;foo="bar"; `, "foo", "bar", "; "},
		{`;foo="bar"; foo=baz`, "foo", "bar", "; foo=baz"},
		{` ; boundary=----CUT;`, "boundary", "----CUT", ";"},
		{` ; key=value;  blah="value";name="foo" `, "key", "value", `;  blah="value";name="foo" `},
		{`;  blah="value";name="foo" `, "blah", "value", `;name="foo" `},
		{`;name="foo" `, "name", "foo", ` `},
	}
	for _, test := range tests {
		param, value, rest := consumeMediaParam(test[0])
		expectedParam := test[1]
		expectedValue := test[2]
		expectedRest := test[3]
		if param != expectedParam {
			t.Errorf("expected to consume param [%s], not [%s] from [%s]",
				expectedParam, param, test[0])
		} else if value != expectedValue {
			t.Errorf("expected to consume value [%s], not [%s] from [%s]",
				expectedValue, value, test[0])
		} else if rest != expectedRest {
			t.Errorf("expected to have left [%s], not [%s] after reading [%s/%s] from [%s]",
				expectedRest, rest, param, value, test[0])
		}
	}
}

type mediaTypeTest struct {
	in string
	t  string
	p  map[string]string
}

func TestParseMediaType(t *testing.T) {
	// Convenience map initializer
	m := func(s ...string) map[string]string {
		sm := make(map[string]string)
		for i := 0; i < len(s); i += 2 {
			sm[s[i]] = s[i+1]
		}
		return sm
	}

	nameFoo := map[string]string{"name": "foo"}
	tests := []mediaTypeTest{
		{`form-data; name="foo"`, "form-data", nameFoo},
		{` form-data ; name=foo`, "form-data", nameFoo},
		{`FORM-DATA;name="foo"`, "form-data", nameFoo},
		{` FORM-DATA ; name="foo"`, "form-data", nameFoo},
		{` FORM-DATA ; name="foo"`, "form-data", nameFoo},

		{`form-data; key=value;  blah="value";name="foo" `,
			"form-data",
			m("key", "value", "blah", "value", "name", "foo")},

		{`foo; key=val1; key=the-key-appears-again-which-is-bogus`,
			"", m()},

		// From RFC 2231:
		{`application/x-stuff; title*=us-ascii'en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A`,
			"application/x-stuff",
			m("title", "This is ***fun***")},

		{`message/external-body; access-type=URL; ` +
			`URL*0="ftp://";` +
			`URL*1="cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar"`,
			"message/external-body",
			m("access-type", "URL",
				"url", "ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar")},

		{`application/x-stuff; ` +
			`title*0*=us-ascii'en'This%20is%20even%20more%20; ` +
			`title*1*=%2A%2A%2Afun%2A%2A%2A%20; ` +
			`title*2="isn't it!"`,
			"application/x-stuff",
			m("title", "This is even more ***fun*** isn't it!")},

		// Tests from http://greenbytes.de/tech/tc2231/
		// Note: Backslash escape handling is a bit loose, like MSIE.

		// #attonly
		{`attachment`,
			"attachment",
			m()},
		// #attonlyucase
		{`ATTACHMENT`,
			"attachment",
			m()},
		// #attwithasciifilename
		{`attachment; filename="foo.html"`,
			"attachment",
			m("filename", "foo.html")},
		// #attwithasciifilename25
		{`attachment; filename="0000000000111111111122222"`,
			"attachment",
			m("filename", "0000000000111111111122222")},
		// #attwithasciifilename35
		{`attachment; filename="00000000001111111111222222222233333"`,
			"attachment",
			m("filename", "00000000001111111111222222222233333")},
		// #attwithasciifnescapedchar
		{`attachment; filename="f\oo.html"`,
			"attachment",
			m("filename", "f\\oo.html")},
		// #attwithasciifnescapedquote
		{`attachment; filename="\"quoting\" tested.html"`,
			"attachment",
			m("filename", `"quoting" tested.html`)},
		// #attwithquotedsemicolon
		{`attachment; filename="Here's a semicolon;.html"`,
			"attachment",
			m("filename", "Here's a semicolon;.html")},
		// #attwithfilenameandextparam
		{`attachment; foo="bar"; filename="foo.html"`,
			"attachment",
			m("foo", "bar", "filename", "foo.html")},
		// #attwithfilenameandextparamescaped
		{`attachment; foo="\"\\";filename="foo.html"`,
			"attachment",
			m("foo", "\"\\", "filename", "foo.html")},
		// #attwithasciifilenameucase
		{`attachment; FILENAME="foo.html"`,
			"attachment",
			m("filename", "foo.html")},
		// #attwithasciifilenamenq
		{`attachment; filename=foo.html`,
			"attachment",
			m("filename", "foo.html")},
		// #attwithasciifilenamenqs
		{`attachment; filename=foo.html ;`,
			"attachment",
			m("filename", "foo.html")},
		// #attwithfntokensq
		{`attachment; filename='foo.html'`,
			"attachment",
			m("filename", "'foo.html'")},
		// #attwithisofnplain
		{`attachment; filename="foo-ä.html"`,
			"attachment",
			m("filename", "foo-ä.html")},
		// #attwithutf8fnplain
		{`attachment; filename="foo-Ã¤.html"`,
			"attachment",
			m("filename", "foo-Ã¤.html")},
		// #attwithfnrawpctenca
		{`attachment; filename="foo-%41.html"`,
			"attachment",
			m("filename", "foo-%41.html")},
		// #attwithfnusingpct
		{`attachment; filename="50%.html"`,
			"attachment",
			m("filename", "50%.html")},
		// #attwithfnrawpctencaq
		{`attachment; filename="foo-%\41.html"`,
			"attachment",
			m("filename", "foo-%\\41.html")},
		// #attwithnamepct
		{`attachment; name="foo-%41.html"`,
			"attachment",
			m("name", "foo-%41.html")},
		// #attwithfilenamepctandiso
		{`attachment; name="ä-%41.html"`,
			"attachment",
			m("name", "ä-%41.html")},
		// #attwithfnrawpctenclong
		{`attachment; filename="foo-%c3%a4-%e2%82%ac.html"`,
			"attachment",
			m("filename", "foo-%c3%a4-%e2%82%ac.html")},
		// #attwithasciifilenamews1
		{`attachment; filename ="foo.html"`,
			"attachment",
			m("filename", "foo.html")},
		// #attmissingdisposition
		{`filename=foo.html`,
			"", m()},
		// #attmissingdisposition2
		{`x=y; filename=foo.html`,
			"", m()},
		// #attmissingdisposition3
		{`"foo; filename=bar;baz"; filename=qux`,
			"", m()},
		// #attmissingdisposition4
		{`filename=foo.html, filename=bar.html`,
			"", m()},
		// #emptydisposition
		{`; filename=foo.html`,
			"", m()},
		// #doublecolon
		{`: inline; attachment; filename=foo.html`,
			"", m()},
		// #attandinline
		{`inline; attachment; filename=foo.html`,
			"", m()},
		// #attandinline2
		{`attachment; inline; filename=foo.html`,
			"", m()},
		// #attbrokenquotedfn
		{`attachment; filename="foo.html".txt`,
			"", m()},
		// #attbrokenquotedfn2
		{`attachment; filename="bar`,
			"", m()},
		// #attbrokenquotedfn3
		{`attachment; filename=foo"bar;baz"qux`,
			"", m()},
		// #attmultinstances
		{`attachment; filename=foo.html, attachment; filename=bar.html`,
			"", m()},
		// #attmissingdelim
		{`attachment; foo=foo filename=bar`,
			"", m()},
		// #attmissingdelim2
		{`attachment; filename=bar foo=foo`,
			"", m()},
		// #attmissingdelim3
		{`attachment filename=bar`,
			"", m()},
		// #attreversed
		{`filename=foo.html; attachment`,
			"", m()},
		// #attconfusedparam
		{`attachment; xfilename=foo.html`,
			"attachment",
			m("xfilename", "foo.html")},
		// #attcdate
		{`attachment; creation-date="Wed, 12 Feb 1997 16:29:51 -0500"`,
			"attachment",
			m("creation-date", "Wed, 12 Feb 1997 16:29:51 -0500")},
		// #attmdate
		{`attachment; modification-date="Wed, 12 Feb 1997 16:29:51 -0500"`,
			"attachment",
			m("modification-date", "Wed, 12 Feb 1997 16:29:51 -0500")},
		// #dispext
		{`foobar`, "foobar", m()},
		// #dispextbadfn
		{`attachment; example="filename=example.txt"`,
			"attachment",
			m("example", "filename=example.txt")},
		// #attwithfn2231utf8
		{`attachment; filename*=UTF-8''foo-%c3%a4-%e2%82%ac.html`,
			"attachment",
			m("filename", "foo-ä-€.html")},
		// #attwithfn2231noc
		{`attachment; filename*=''foo-%c3%a4-%e2%82%ac.html`,
			"attachment",
			m()},
		// #attwithfn2231utf8comp
		{`attachment; filename*=UTF-8''foo-a%cc%88.html`,
			"attachment",
			m("filename", "foo-ä.html")},
		// #attwithfn2231ws2
		{`attachment; filename*= UTF-8''foo-%c3%a4.html`,
			"attachment",
			m("filename", "foo-ä.html")},
		// #attwithfn2231ws3
		{`attachment; filename* =UTF-8''foo-%c3%a4.html`,
			"attachment",
			m("filename", "foo-ä.html")},
		// #attwithfn2231quot
		{`attachment; filename*="UTF-8''foo-%c3%a4.html"`,
			"attachment",
			m("filename", "foo-ä.html")},
		// #attwithfn2231quot2
		{`attachment; filename*="foo%20bar.html"`,
			"attachment",
			m()},
		// #attwithfn2231singleqmissing
		{`attachment; filename*=UTF-8'foo-%c3%a4.html`,
			"attachment",
			m()},
		// #attwithfn2231nbadpct1
		{`attachment; filename*=UTF-8''foo%`,
			"attachment",
			m()},
		// #attwithfn2231nbadpct2
		{`attachment; filename*=UTF-8''f%oo.html`,
			"attachment",
			m()},
		// #attwithfn2231dpct
		{`attachment; filename*=UTF-8''A-%2541.html`,
			"attachment",
			m("filename", "A-%41.html")},
		// #attfncont
		{`attachment; filename*0="foo."; filename*1="html"`,
			"attachment",
			m("filename", "foo.html")},
		// #attfncontenc
		{`attachment; filename*0*=UTF-8''foo-%c3%a4; filename*1=".html"`,
			"attachment",
			m("filename", "foo-ä.html")},
		// #attfncontlz
		{`attachment; filename*0="foo"; filename*01="bar"`,
			"attachment",
			m("filename", "foo")},
		// #attfncontnc
		{`attachment; filename*0="foo"; filename*2="bar"`,
			"attachment",
			m("filename", "foo")},
		// #attfnconts1
		{`attachment; filename*1="foo."; filename*2="html"`,
			"attachment", m()},
		// #attfncontord
		{`attachment; filename*1="bar"; filename*0="foo"`,
			"attachment",
			m("filename", "foobar")},
		// #attfnboth
		{`attachment; filename="foo-ae.html"; filename*=UTF-8''foo-%c3%a4.html`,
			"attachment",
			m("filename", "foo-ä.html")},
		// #attfnboth2
		{`attachment; filename*=UTF-8''foo-%c3%a4.html; filename="foo-ae.html"`,
			"attachment",
			m("filename", "foo-ä.html")},
		// #attfnboth3
		{`attachment; filename*0*=ISO-8859-15''euro-sign%3d%a4; filename*=ISO-8859-1''currency-sign%3d%a4`,
			"attachment",
			m()},
		// #attnewandfn
		{`attachment; foobar=x; filename="foo.html"`,
			"attachment",
			m("foobar", "x", "filename", "foo.html")},

		// Browsers also just send UTF-8 directly without RFC 2231,
		// at least when the source page is served with UTF-8.
		{`form-data; firstname="Брэд"; lastname="Фицпатрик"`,
			"form-data",
			m("firstname", "Брэд", "lastname", "Фицпатрик")},

		// Empty string used to be mishandled.
		{`foo; bar=""`, "foo", m("bar", "")},

		// Microsoft browsers in intranet mode do not think they need to escape \ in file name.
		{`form-data; name="file"; filename="C:\dev\go\robots.txt"`, "form-data", m("name", "file", "filename", `C:\dev\go\robots.txt`)},
		{`form-data; name="file"; filename="C:\新建文件夹\中文第二次测试.mp4"`, "form-data", m("name", "file", "filename", `C:\新建文件夹\中文第二次测试.mp4`)},

		// issue #46323 (https://github.com/golang/go/issues/46323)
		{
			// example from rfc2231-p.3 (https://datatracker.ietf.org/doc/html/rfc2231)
			`message/external-body; access-type=URL;
		URL*0="ftp://";
		URL*1="cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar";`, // <-- trailing semicolon
			`message/external-body`,
			m("access-type", "URL", "url", "ftp://cs.utk.edu/pub/moore/bulk-mailer/bulk-mailer.tar"),
		},

		// Issue #48866: duplicate parameters containing equal values should be allowed
		{`text; charset=utf-8; charset=utf-8; format=fixed`, "text", m("charset", "utf-8", "format", "fixed")},
		{`text; charset=utf-8; format=flowed; charset=utf-8`, "text", m("charset", "utf-8", "format", "flowed")},
	}
	for _, test := range tests {
		mt, params, err := ParseMediaType(test.in)
		if err != nil {
			if test.t != "" {
				t.Errorf("for input %#q, unexpected error: %v", test.in, err)
				continue
			}
			continue
		}
		if g, e := mt, test.t; g != e {
			t.Errorf("for input %#q, expected type %q, got %q",
				test.in, e, g)
			continue
		}
		if len(params) == 0 && len(test.p) == 0 {
			continue
		}
		if !maps.Equal(params, test.p) {
			t.Errorf("for input %#q, wrong params.\n"+
				"expected: %#v\n"+
				"     got: %#v",
				test.in, test.p, params)
		}
	}
}

type badMediaTypeTest struct {
	in  string
	mt  string
	err string
}

var badMediaTypeTests = []badMediaTypeTest{
	{"bogus ;=========", "bogus", "mime: invalid media parameter"},
	// The following example is from real email delivered by gmail (error: missing semicolon)
	// and it is there to check behavior described in #19498
	{"application/pdf; x-mac-type=\"3F3F3F3F\"; x-mac-creator=\"3F3F3F3F\" name=\"a.pdf\";",
		"application/pdf", "mime: invalid media parameter"},
	{"bogus/<script>alert</script>", "", "mime: expected token after slash"},
	{"bogus/bogus<script>alert</script>", "", "mime: unexpected content after media subtype"},
	// Tests from http://greenbytes.de/tech/tc2231/
	{`"attachment"`, "attachment", "mime: no media type"},
	{"attachment; filename=foo,bar.html", "attachment", "mime: invalid media parameter"},
	{"attachment; ;filename=foo", "attachment", "mime: invalid media parameter"},
	{"attachment; filename=foo bar.html", "attachment", "mime: invalid media parameter"},
	{`attachment; filename="foo.html"; filename="bar.html"`, "attachment", "mime: duplicate parameter name"},
	{"attachment; filename=foo[1](2).html", "attachment", "mime: invalid media parameter"},
	{"attachment; filename=foo-ä.html", "attachment", "mime: invalid media parameter"},
	{"attachment; filename=foo-Ã¤.html", "attachment", "mime: invalid media parameter"},
	{`attachment; filename *=UTF-8''foo-%c3%a4.html`, "attachment", "mime: invalid media parameter"},
}

func TestParseMediaTypeBogus(t *testing.T) {
	for _, tt := range badMediaTypeTests {
		mt, params, err := ParseMediaType(tt.in)
		if err == nil {
			t.Errorf("ParseMediaType(%q) = nil error; want parse error", tt.in)
			continue
		}
		if err.Error() != tt.err {
			t.Errorf("ParseMediaType(%q) = err %q; want %q", tt.in, err.Error(), tt.err)
		}
		if params != nil {
			t.Errorf("ParseMediaType(%q): got non-nil params on error", tt.in)
		}
		if err != ErrInvalidMediaParameter && mt != "" {
			t.Errorf("ParseMediaType(%q): got unexpected non-empty media type string", tt.in)
		}
		if err == ErrInvalidMediaParameter && mt != tt.mt {
			t.Errorf("ParseMediaType(%q): in case of invalid parameters: expected type %q, got %q", tt.in, tt.mt, mt)
		}
	}
}

type formatTest struct {
	typ    string
	params map[string]string
	want   string
}

var formatTests = []formatTest{
	{"noslash", map[string]string{"X": "Y"}, "noslash; x=Y"}, // e.g. Content-Disposition values (RFC 2183); issue 11289
	{"foo bar/baz", nil, ""},
	{"foo/bar baz", nil, ""},
	{"attachment", map[string]string{"filename": "ĄĄŽŽČČŠŠ"}, "attachment; filename*=utf-8''%C4%84%C4%84%C5%BD%C5%BD%C4%8C%C4%8C%C5%A0%C5%A0"},
	{"attachment", map[string]string{"filename": "ÁÁÊÊÇÇÎÎ"}, "attachment; filename*=utf-8''%C3%81%C3%81%C3%8A%C3%8A%C3%87%C3%87%C3%8E%C3%8E"},
	{"attachment", map[string]string{"filename": "数据统计.png"}, "attachment; filename*=utf-8''%E6%95%B0%E6%8D%AE%E7%BB%9F%E8%AE%A1.png"},
	{"foo/BAR", nil, "foo/bar"},
	{"foo/BAR", map[string]string{"X": "Y"}, "foo/bar; x=Y"},
	{"foo/BAR", map[string]string{"space": "With space"}, `foo/bar; space="With space"`},
	{"foo/BAR", map[string]string{"quote": `With "quote`}, `foo/bar; quote="With \"quote"`},
	{"foo/BAR", map[string]string{"bslash": `With \backslash`}, `foo/bar; bslash="With \\backslash"`},
	{"foo/BAR", map[string]string{"both": `With \backslash and "quote`}, `foo/bar; both="With \\backslash and \"quote"`},
	{"foo/BAR", map[string]string{"": "empty attribute"}, ""},
	{"foo/BAR", map[string]string{"bad attribute": "baz"}, ""},
	{"foo/BAR", map[string]string{"nonascii": "not an ascii character: ä"}, "foo/bar; nonascii*=utf-8''not%20an%20ascii%20character%3A%20%C3%A4"},
	{"foo/BAR", map[string]string{"ctl": "newline: \n nil: \000"}, "foo/bar; ctl*=utf-8''newline%3A%20%0A%20nil%3A%20%00"},
	{"foo/bar", map[string]string{"a": "av", "b": "bv", "c": "cv"}, "foo/bar; a=av; b=bv; c=cv"},
	{"foo/bar", map[string]string{"0": "'", "9": "'"}, "foo/bar; 0='; 9='"},
	{"foo", map[string]string{"bar": ""}, `foo; bar=""`},
}

func TestFormatMediaType(t *testing.T) {
	for i, tt := range formatTests {
		got := FormatMediaType(tt.typ, tt.params)
		if got != tt.want {
			t.Errorf("%d. FormatMediaType(%q, %v) = %q; want %q", i, tt.typ, tt.params, got, tt.want)
		}
		if got == "" {
			continue
		}
		typ, params, err := ParseMediaType(got)
		if err != nil {
			t.Errorf("%d. ParseMediaType(%q) err: %v", i, got, err)
		}
		if typ != strings.ToLower(tt.typ) {
			t.Errorf("%d. ParseMediaType(%q) typ = %q; want %q", i, got, typ, tt.typ)
		}
		for k, v := range tt.params {
			k = strings.ToLower(k)
			if params[k] != v {
				t.Errorf("%d. ParseMediaType(%q) params[%s] = %q; want %q", i, got, k, params[k], v)
			}
		}
	}
}

"""



```