Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Identify the Core Purpose:** The code resides in `go/src/net/url/example_test.go`. The name itself suggests it's about testing examples for the `net/url` package. The presence of `Example` prefixed functions confirms this. These examples demonstrate how to use various functions and types within the `net/url` package.

2. **Categorize the Functionality:** Scan through the `Example` functions and group them by the `net/url` feature they demonstrate. This gives a structured overview:

    * **Escaping/Unescaping:** `PathEscape`, `PathUnescape`, `QueryEscape`, `QueryUnescape`.
    * **Query Parameters (Values type):** `Values`, `Values_Add`, `Values_Del`, `Values_Encode`, `Values_Get`, `Values_Has`, `Values_Set`.
    * **URL Manipulation (URL type):** `URL`, `URL_roundtrip`, `URL_ResolveReference`, `URL_EscapedPath`, `URL_EscapedFragment`, `URL_Hostname`, `URL_IsAbs`, `URL_JoinPath`, `URL_MarshalBinary`, `URL_Parse`, `URL_Port`, `URL_Query`, `URL_String`, `URL_UnmarshalBinary`, `URL_Redacted`, `URL_RequestURI`.
    * **Query Parsing:** `ParseQuery`.

3. **Analyze Each Example Function:** For each `Example` function:

    * **Identify the Core Function/Method:** What `net/url` function or method is being demonstrated?
    * **Understand the Input:** What data is being passed to the function/method?  Is it a string, a `url.Values` object, or a `url.URL` object?
    * **Understand the Operation:** What action is the function/method performing (escaping, unescaping, adding/getting/setting query parameters, parsing a URL, etc.)?
    * **Understand the Output:** What is the expected output? This is explicitly provided in the `// Output:` comments.
    * **Connect to the broader `net/url` package functionality:** How does this specific example fit into the larger purpose of the `net/url` package (handling URLs)?

4. **Infer Go Language Features Illustrated:**  Based on the examples, list the Go features being showcased:

    * **String manipulation:** Escaping and unescaping.
    * **Data structures:**  The `url.Values` type (map-like for query parameters) and the `url.URL` struct.
    * **Error handling:** The consistent `if err != nil` pattern.
    * **Method calls on structs:**  Demonstrating how to use methods of `url.Values` and `url.URL`.
    * **String formatting:** Using `fmt.Println` and `fmt.Printf`.
    * **Parsing:** `url.Parse` and `url.ParseQuery`.
    * **Encoding/Decoding:**  `url.Values.Encode()`.
    * **Binary Marshalling/Unmarshalling:** `MarshalBinary` and `UnmarshalBinary`.

5. **Illustrate with Go Code Examples (if necessary for clarity):** For more complex functionalities, or to show the interaction between different parts of the package, create simplified code examples. This wasn't strictly *required* by the prompt since the `Example` functions already served this purpose, but it's a helpful step in understanding. For instance, if the `Values` example was less clear, one might write a small program to demonstrate how `Set` overwrites while `Add` appends.

6. **Consider Command-Line Arguments (not applicable here):** The prompt asks about command-line arguments. This code doesn't directly interact with command-line arguments. Note this and move on.

7. **Identify Potential Pitfalls:** Think about common mistakes users might make when using these functions. This involves considering edge cases and the specific behavior of each function. For example:

    * Confusing `PathEscape` and `QueryEscape`.
    * Expecting `Get` on `url.Values` to return all values (it only returns the first).
    * Not checking errors from parsing functions.
    * Misunderstanding the difference between `Path` and `RawPath`.

8. **Structure the Answer:**  Organize the findings into clear sections as requested by the prompt: functionalities, Go language features, code examples, command-line arguments, and common mistakes. Use clear and concise language.

9. **Review and Refine:** Read through the answer to ensure accuracy, completeness, and clarity. Make sure all parts of the prompt have been addressed.

Essentially, the process is about understanding the code's *purpose*, dissecting its *components*, and then synthesizing that understanding into a coherent explanation. The `Example` function naming convention in Go is a huge help in this process, as it explicitly points to the features being demonstrated.
这个Go语言文件 `go/src/net/url/example_test.go` 的主要功能是**提供 `net/url` 包中各种函数和类型的用法示例**。 这些示例旨在帮助开发者理解如何使用 `net/url` 包来处理和操作 URL。

下面列举了代码中各个示例展示的功能，并附带了相关的解释和代码示例：

**1. URL 编码与解码:**

*   **`ExamplePathEscape()` 和 `ExamplePathUnescape()`:**  演示了如何对 URL 路径部分进行编码和解码。`PathEscape` 会转义路径中可能引起歧义的字符，例如 `/`，但保留 `+`。 `PathUnescape` 则执行相反的操作。

    ```go
    package main

    import (
        "fmt"
        "log"
        "net/url"
    )

    func main() {
        path := "my/cool+blog&about,stuff"
        escapedPath := url.PathEscape(path)
        fmt.Println("编码后的路径:", escapedPath) // 输出: 编码后的路径: my%2Fcool+blog&about%2Cstuff

        unescapedPath, err := url.PathUnescape(escapedPath)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("解码后的路径:", unescapedPath) // 输出: 解码后的路径: my/cool+blog&about,stuff
    }
    ```

    **假设输入:** 字符串 "my/cool+blog&about,stuff"
    **输出:**
    *   `PathEscape`: "my%2Fcool+blog&about%2Cstuff"
    *   `PathUnescape`: "my/cool+blog&about,stuff"

*   **`ExampleQueryEscape()` 和 `ExampleQueryUnescape()`:** 演示了如何对 URL 查询参数部分进行编码和解码。`QueryEscape` 会转义查询参数中可能引起歧义的字符，例如 `/`、`+` 和 `&`。 `QueryUnescape` 则执行相反的操作。

    ```go
    package main

    import (
        "fmt"
        "log"
        "net/url"
    )

    func main() {
        query := "my/cool+blog&about,stuff"
        escapedQuery := url.QueryEscape(query)
        fmt.Println("编码后的查询:", escapedQuery) // 输出: 编码后的查询: my%2Fcool%2Bblog%26about%2Cstuff

        unescapedQuery, err := url.QueryUnescape(escapedQuery)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println("解码后的查询:", unescapedQuery) // 输出: 解码后的查询: my/cool+blog&about,stuff
    }
    ```

    **假设输入:** 字符串 "my/cool+blog&about,stuff"
    **输出:**
    *   `QueryEscape`: "my%2Fcool%2Bblog%26about%2Cstuff"
    *   `QueryUnescape`: "my/cool+blog&about,stuff"

**2. 处理 URL 查询参数 (`url.Values`):**

*   **`ExampleValues()`:** 展示了 `url.Values` 类型的使用，它是一个 `map[string][]string`，用于存储查询参数。 示例演示了 `Set` (设置单个值)、`Add` (添加多个值)、`Get` (获取指定键的第一个值) 以及直接通过 map 访问获取所有值的方法。

    ```go
    package main

    import (
        "fmt"
        "net/url"
    )

    func main() {
        v := url.Values{}
        v.Set("name", "Ava")
        v.Add("friend", "Jess")
        v.Add("friend", "Sarah")
        v.Add("friend", "Zoe")

        fmt.Println("Name:", v.Get("name"))      // 输出: Name: Ava
        fmt.Println("First Friend:", v.Get("friend")) // 输出: First Friend: Jess
        fmt.Println("All Friends:", v["friend"])    // 输出: All Friends: [Jess Sarah Zoe]
    }
    ```

    **假设的内部 `v` 的状态:** `map[string][]string{"name": ["Ava"], "friend": ["Jess", "Sarah", "Zoe"]}`
    **输出:**
    *   `v.Get("name")`: "Ava"
    *   `v.Get("friend")`: "Jess"
    *   `v["friend"]`: `[]string{"Jess", "Sarah", "Zoe"}`

*   **`ExampleValues_Add()`:** 演示了 `Add` 方法如何为一个键添加多个值。

*   **`ExampleValues_Del()`:** 演示了 `Del` 方法如何删除指定键的所有值。

*   **`ExampleValues_Encode()`:** 演示了 `Encode` 方法如何将 `url.Values` 编码为 URL 查询字符串。

    ```go
    package main

    import (
        "fmt"
        "net/url"
    )

    func main() {
        v := url.Values{}
        v.Add("cat sounds", "meow")
        v.Add("cat sounds", "mew/")
        v.Add("cat sounds", "mau$")
        fmt.Println(v.Encode()) // 输出: cat+sounds=meow&cat+sounds=mew%2F&cat+sounds=mau%24
    }
    ```

    **假设的内部 `v` 的状态:** `map[string][]string{"cat sounds": ["meow", "mew/", "mau$"]}`
    **输出:** "cat+sounds=meow&cat+sounds=mew%2F&cat+sounds=mau%24"

*   **`ExampleValues_Get()`:**  再次强调 `Get` 方法只返回指定键的第一个值。

*   **`ExampleValues_Has()`:** 演示了 `Has` 方法如何检查 `url.Values` 中是否存在指定的键。

*   **`ExampleValues_Set()`:** 演示了 `Set` 方法如何设置指定键的值，如果该键已存在，则会覆盖所有旧的值。

**3. 操作 `url.URL` 结构体:**

*   **`ExampleURL()`:** 展示了如何使用 `url.Parse` 解析 URL 字符串，并修改 `url.URL` 结构体的字段，例如 `Scheme`、`Host` 和 `RawQuery`。

    ```go
    package main

    import (
        "fmt"
        "log"
        "net/url"
    )

    func main() {
        u, err := url.Parse("http://bing.com/search?q=dotnet")
        if err != nil {
            log.Fatal(err)
        }
        u.Scheme = "https"
        u.Host = "google.com"
        q := u.Query()
        q.Set("q", "golang")
        u.RawQuery = q.Encode()
        fmt.Println(u) // 输出: https://google.com/search?q=golang
    }
    ```

    **假设输入:** URL 字符串 "http://bing.com/search?q=dotnet"
    **操作:** 修改 Scheme 为 "https"，Host 为 "google.com"，并修改查询参数 "q" 的值为 "golang"。
    **输出:** "https://google.com/search?q=golang"

*   **`ExampleURL_roundtrip()`:**  演示了 `url.Parse` 和 `url.URL.String()` 方法在处理已编码路径时的行为，强调它们会保留原始编码。

*   **`ExampleURL_ResolveReference()`:** 展示了 `ResolveReference` 方法如何解析一个相对于基本 URL 的引用 URL。

*   **`ExampleURL_EscapedPath()` 和 `ExampleURL_EscapedFragment()`:**  演示了 `EscapedPath` 和 `EscapedFragment` 方法返回的是 URL 中已转义的路径和片段部分。

*   **`ExampleURL_Hostname()`:** 展示了 `Hostname` 方法如何获取 URL 的主机名，包括 IPv6 地址。

*   **`ExampleURL_IsAbs()`:** 演示了 `IsAbs` 方法如何判断 URL 是否是绝对 URL（是否包含 Scheme）。

*   **`ExampleURL_JoinPath()`:** 展示了 `JoinPath` 方法如何将给定的路径片段安全地添加到 URL 的路径中。

*   **`ExampleURL_MarshalBinary()` 和 `ExampleURL_UnmarshalBinary()`:**  演示了 `url.URL` 如何实现 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口，可以进行二进制序列化和反序列化。

*   **`ExampleURL_Parse()`:** 演示了 `url.URL.Parse` 方法用于解析相对于当前 URL 的另一个 URL。

*   **`ExampleURL_Port()`:** 展示了 `Port` 方法如何获取 URL 的端口号。

*   **`ExampleURL_Query()`:** 演示了 `Query` 方法如何获取 URL 的查询参数，返回一个 `url.Values` 类型的值。

*   **`ExampleURL_String()`:** 展示了 `String` 方法如何将 `url.URL` 结构体转换为字符串形式。注意 `Opaque` 字段会影响输出格式。

*   **`ExampleURL_Redacted()`:** 展示了 `Redacted` 方法如何返回一个隐藏了用户密码的 URL 字符串。

*   **`ExampleURL_RequestURI()`:** 展示了 `RequestURI` 方法如何获取 URL 的请求 URI 部分（路径和查询参数）。

**4. 解析查询字符串 (`url.ParseQuery`):**

*   **`ExampleParseQuery()`:** 演示了 `url.ParseQuery` 函数如何将查询字符串解析为 `url.Values` 类型。

    ```go
    package main

    import (
        "encoding/json"
        "fmt"
        "log"
        "net/url"
        "strings"
    )

    func toJSON(m any) string {
        js, err := json.Marshal(m)
        if err != nil {
            log.Fatal(err)
        }
        return strings.ReplaceAll(string(js), ",", ", ")
    }

    func main() {
        m, err := url.ParseQuery(`x=1&y=2&y=3`)
        if err != nil {
            log.Fatal(err)
        }
        fmt.Println(toJSON(m)) // 输出: {"x": ["1"], "y": ["2", "3"]}
    }
    ```

    **假设输入:** 查询字符串 "x=1&y=2&y=3"
    **输出:** `map[string][]string{"x": ["1"], "y": ["2", "3"]}` (以 JSON 格式化后输出)

**涉及的 Go 语言功能实现:**

*   **字符串处理:**  URL 编码和解码涉及到对字符串的替换和转义。
*   **数据结构:** `url.Values` 是一个 `map`，用于存储键值对形式的查询参数。 `url.URL` 是一个结构体，用于表示 URL 的各个组成部分。
*   **方法:** 提供了各种方法来操作 `url.Values` 和 `url.URL` 类型的实例，例如 `Set`、`Add`、`Get`、`Encode`、`Parse`、`String` 等。
*   **错误处理:**  许多 `net/url` 包的函数会返回错误，例如 `url.Parse` 和 `url.PathUnescape`，需要进行错误处理。
*   **接口:** `url.URL` 实现了 `encoding.BinaryMarshaler` 和 `encoding.BinaryUnmarshaler` 接口。

**命令行参数处理:**

这段代码本身不涉及直接的命令行参数处理。它主要是作为 `net/url` 包的示例代码存在，通常会被其他程序导入并使用。 如果需要在命令行程序中使用 `net/url` 包，你需要使用 `os` 包或者第三方库来获取和处理命令行参数。

**使用者易犯错的点:**

*   **混淆 `PathEscape` 和 `QueryEscape`:**  `PathEscape` 不会转义 `+` 号，而 `QueryEscape` 会转义。这会导致在构建 URL 时出现意外的编码结果。

    ```go
    package main

    import (
        "fmt"
        "net/url"
    )

    func main() {
        text := "search+terms"
        pathEncoded := url.PathEscape(text)
        queryEncoded := url.QueryEscape(text)

        fmt.Println("PathEncoded:", pathEncoded)   // 输出: PathEncoded: search+terms
        fmt.Println("QueryEncoded:", queryEncoded) // 输出: QueryEncoded: search%2Bterms
    }
    ```

    如果你想将包含 `+` 的文本作为查询参数的值，应该使用 `QueryEscape`。

*   **期望 `url.Values.Get()` 返回所有值:**  `Get()` 方法只返回指定键的第一个值。 如果需要获取所有值，需要直接访问 `url.Values` 的 `map`。

    ```go
    package main

    import (
        "fmt"
        "net/url"
    )

    func main() {
        v := url.Values{}
        v.Add("key", "value1")
        v.Add("key", "value2")

        fmt.Println(v.Get("key"))   // 输出: value1
        fmt.Println(v["key"])      // 输出: [value1 value2]
    }
    ```

*   **忘记处理 `url.Parse` 等函数的错误:**  URL 解析可能失败，例如当传入无效的 URL 字符串时。 忽略错误可能导致程序崩溃或其他不可预测的行为。

    ```go
    package main

    import (
        "fmt"
        "log"
        "net/url"
    )

    func main() {
        u, err := url.Parse("invalid url")
        if err != nil {
            log.Println("Error parsing URL:", err)
            return
        }
        fmt.Println(u) // 这行代码只有在解析成功时才会执行
    }
    ```

总而言之，`go/src/net/url/example_test.go` 提供了一系列清晰的示例，展示了 `net/url` 包的核心功能，帮助开发者正确地使用该包来处理 URL 相关的任务。

### 提示词
```
这是路径为go/src/net/url/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package url_test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
)

func ExamplePathEscape() {
	path := url.PathEscape("my/cool+blog&about,stuff")
	fmt.Println(path)

	// Output:
	// my%2Fcool+blog&about%2Cstuff
}

func ExamplePathUnescape() {
	escapedPath := "my%2Fcool+blog&about%2Cstuff"
	path, err := url.PathUnescape(escapedPath)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(path)

	// Output:
	// my/cool+blog&about,stuff
}

func ExampleQueryEscape() {
	query := url.QueryEscape("my/cool+blog&about,stuff")
	fmt.Println(query)

	// Output:
	// my%2Fcool%2Bblog%26about%2Cstuff
}

func ExampleQueryUnescape() {
	escapedQuery := "my%2Fcool%2Bblog%26about%2Cstuff"
	query, err := url.QueryUnescape(escapedQuery)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(query)

	// Output:
	// my/cool+blog&about,stuff
}

func ExampleValues() {
	v := url.Values{}
	v.Set("name", "Ava")
	v.Add("friend", "Jess")
	v.Add("friend", "Sarah")
	v.Add("friend", "Zoe")
	// v.Encode() == "name=Ava&friend=Jess&friend=Sarah&friend=Zoe"
	fmt.Println(v.Get("name"))
	fmt.Println(v.Get("friend"))
	fmt.Println(v["friend"])
	// Output:
	// Ava
	// Jess
	// [Jess Sarah Zoe]
}

func ExampleValues_Add() {
	v := url.Values{}
	v.Add("cat sounds", "meow")
	v.Add("cat sounds", "mew")
	v.Add("cat sounds", "mau")
	fmt.Println(v["cat sounds"])

	// Output:
	// [meow mew mau]
}

func ExampleValues_Del() {
	v := url.Values{}
	v.Add("cat sounds", "meow")
	v.Add("cat sounds", "mew")
	v.Add("cat sounds", "mau")
	fmt.Println(v["cat sounds"])

	v.Del("cat sounds")
	fmt.Println(v["cat sounds"])

	// Output:
	// [meow mew mau]
	// []
}

func ExampleValues_Encode() {
	v := url.Values{}
	v.Add("cat sounds", "meow")
	v.Add("cat sounds", "mew/")
	v.Add("cat sounds", "mau$")
	fmt.Println(v.Encode())

	// Output:
	// cat+sounds=meow&cat+sounds=mew%2F&cat+sounds=mau%24
}

func ExampleValues_Get() {
	v := url.Values{}
	v.Add("cat sounds", "meow")
	v.Add("cat sounds", "mew")
	v.Add("cat sounds", "mau")
	fmt.Printf("%q\n", v.Get("cat sounds"))
	fmt.Printf("%q\n", v.Get("dog sounds"))

	// Output:
	// "meow"
	// ""
}

func ExampleValues_Has() {
	v := url.Values{}
	v.Add("cat sounds", "meow")
	v.Add("cat sounds", "mew")
	v.Add("cat sounds", "mau")
	fmt.Println(v.Has("cat sounds"))
	fmt.Println(v.Has("dog sounds"))

	// Output:
	// true
	// false
}

func ExampleValues_Set() {
	v := url.Values{}
	v.Add("cat sounds", "meow")
	v.Add("cat sounds", "mew")
	v.Add("cat sounds", "mau")
	fmt.Println(v["cat sounds"])

	v.Set("cat sounds", "meow")
	fmt.Println(v["cat sounds"])

	// Output:
	// [meow mew mau]
	// [meow]
}

func ExampleURL() {
	u, err := url.Parse("http://bing.com/search?q=dotnet")
	if err != nil {
		log.Fatal(err)
	}
	u.Scheme = "https"
	u.Host = "google.com"
	q := u.Query()
	q.Set("q", "golang")
	u.RawQuery = q.Encode()
	fmt.Println(u)
	// Output: https://google.com/search?q=golang
}

func ExampleURL_roundtrip() {
	// Parse + String preserve the original encoding.
	u, err := url.Parse("https://example.com/foo%2fbar")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Path)
	fmt.Println(u.RawPath)
	fmt.Println(u.String())
	// Output:
	// /foo/bar
	// /foo%2fbar
	// https://example.com/foo%2fbar
}

func ExampleURL_ResolveReference() {
	u, err := url.Parse("../../..//search?q=dotnet")
	if err != nil {
		log.Fatal(err)
	}
	base, err := url.Parse("http://example.com/directory/")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(base.ResolveReference(u))
	// Output:
	// http://example.com/search?q=dotnet
}

func ExampleParseQuery() {
	m, err := url.ParseQuery(`x=1&y=2&y=3`)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(toJSON(m))
	// Output:
	// {"x":["1"], "y":["2", "3"]}
}

func ExampleURL_EscapedPath() {
	u, err := url.Parse("http://example.com/x/y%2Fz")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Path:", u.Path)
	fmt.Println("RawPath:", u.RawPath)
	fmt.Println("EscapedPath:", u.EscapedPath())
	// Output:
	// Path: /x/y/z
	// RawPath: /x/y%2Fz
	// EscapedPath: /x/y%2Fz
}

func ExampleURL_EscapedFragment() {
	u, err := url.Parse("http://example.com/#x/y%2Fz")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Fragment:", u.Fragment)
	fmt.Println("RawFragment:", u.RawFragment)
	fmt.Println("EscapedFragment:", u.EscapedFragment())
	// Output:
	// Fragment: x/y/z
	// RawFragment: x/y%2Fz
	// EscapedFragment: x/y%2Fz
}

func ExampleURL_Hostname() {
	u, err := url.Parse("https://example.org:8000/path")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Hostname())
	u, err = url.Parse("https://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:17000")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Hostname())
	// Output:
	// example.org
	// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
}

func ExampleURL_IsAbs() {
	u := url.URL{Host: "example.com", Path: "foo"}
	fmt.Println(u.IsAbs())
	u.Scheme = "http"
	fmt.Println(u.IsAbs())
	// Output:
	// false
	// true
}

func ExampleURL_JoinPath() {
	u, err := url.Parse("https://example.com/foo/bar")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(u.JoinPath("baz", "qux"))

	// Output:
	// https://example.com/foo/bar/baz/qux
}

func ExampleURL_MarshalBinary() {
	u, _ := url.Parse("https://example.org")
	b, err := u.MarshalBinary()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", b)
	// Output:
	// https://example.org
}

func ExampleURL_Parse() {
	u, err := url.Parse("https://example.org")
	if err != nil {
		log.Fatal(err)
	}
	rel, err := u.Parse("/foo")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rel)
	_, err = u.Parse(":foo")
	if _, ok := err.(*url.Error); !ok {
		log.Fatal(err)
	}
	// Output:
	// https://example.org/foo
}

func ExampleURL_Port() {
	u, err := url.Parse("https://example.org")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Port())
	u, err = url.Parse("https://example.org:8080")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.Port())
	// Output:
	//
	// 8080
}

func ExampleURL_Query() {
	u, err := url.Parse("https://example.org/?a=1&a=2&b=&=3&&&&")
	if err != nil {
		log.Fatal(err)
	}
	q := u.Query()
	fmt.Println(q["a"])
	fmt.Println(q.Get("b"))
	fmt.Println(q.Get(""))
	// Output:
	// [1 2]
	//
	// 3
}

func ExampleURL_String() {
	u := &url.URL{
		Scheme:   "https",
		User:     url.UserPassword("me", "pass"),
		Host:     "example.com",
		Path:     "foo/bar",
		RawQuery: "x=1&y=2",
		Fragment: "anchor",
	}
	fmt.Println(u.String())
	u.Opaque = "opaque"
	fmt.Println(u.String())
	// Output:
	// https://me:pass@example.com/foo/bar?x=1&y=2#anchor
	// https:opaque?x=1&y=2#anchor
}

func ExampleURL_UnmarshalBinary() {
	u := &url.URL{}
	err := u.UnmarshalBinary([]byte("https://example.org/foo"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", u)
	// Output:
	// https://example.org/foo
}

func ExampleURL_Redacted() {
	u := &url.URL{
		Scheme: "https",
		User:   url.UserPassword("user", "password"),
		Host:   "example.com",
		Path:   "foo/bar",
	}
	fmt.Println(u.Redacted())
	u.User = url.UserPassword("me", "newerPassword")
	fmt.Println(u.Redacted())
	// Output:
	// https://user:xxxxx@example.com/foo/bar
	// https://me:xxxxx@example.com/foo/bar
}

func ExampleURL_RequestURI() {
	u, err := url.Parse("https://example.org/path?foo=bar")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(u.RequestURI())
	// Output: /path?foo=bar
}

func toJSON(m any) string {
	js, err := json.Marshal(m)
	if err != nil {
		log.Fatal(err)
	}
	return strings.ReplaceAll(string(js), ",", ", ")
}
```