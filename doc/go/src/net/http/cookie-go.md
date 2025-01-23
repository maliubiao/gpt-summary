Response:
我的思考过程如下：

1. **理解代码目标和上下文:**  首先，我注意到代码的开头注释 `// Copyright 2009 The Go Authors. All rights reserved.` 和 `package http`，这表明这是 Go 标准库 `net/http` 包的一部分。文件名 `cookie.go` 也直接暗示了这部分代码与 HTTP Cookie 的处理有关。

2. **识别关键结构体:** 我快速浏览代码，寻找核心的数据结构。`Cookie` 结构体非常显眼，它包含了 Cookie 的各种属性，例如 `Name`, `Value`, `Path`, `Domain`, `Expires` 等。这证实了我的初步判断：这段代码是关于 HTTP Cookie 的。`SameSite` 枚举也引起了我的注意，它表示 Cookie 的 SameSite 属性。

3. **分析核心功能函数:** 接下来，我关注了主要的函数：
    * `ParseCookie(line string) ([]*Cookie, error)`:  函数名很直白，就是解析 `Cookie` 请求头字符串。
    * `ParseSetCookie(line string) (*Cookie, error)`:  同样直白，解析 `Set-Cookie` 响应头字符串。
    * `readSetCookies(h Header) []*Cookie`:  从 `Header` 中读取所有的 `Set-Cookie` 头。
    * `SetCookie(w ResponseWriter, cookie *Cookie)`:  向 `ResponseWriter` 中添加 `Set-Cookie` 头。
    * `String() string`:  将 `Cookie` 结构体序列化为字符串，用于 `Cookie` 或 `Set-Cookie` 头。
    * `Valid() error`:  验证 `Cookie` 结构体是否有效。
    * `readCookies(h Header, filter string) []*Cookie`: 从 `Header` 中读取所有的 `Cookie` 头，并可以根据名字进行过滤。

4. **推理 Go 语言功能实现:** 基于以上分析，我可以推断出这段代码实现了 Go 语言中处理 HTTP Cookie 的核心功能。它提供了解析、创建、序列化和验证 Cookie 的能力。

5. **代码举例说明:** 为了更具体地说明功能，我决定用 `ParseSetCookie` 和 `SetCookie` 这两个核心函数来举例。
    * **`ParseSetCookie`:**  我需要一个 `Set-Cookie` 头的字符串作为输入，并展示解析后的 `Cookie` 结构体。我选择了一个包含多个属性的典型 `Set-Cookie` 头。
    * **`SetCookie`:** 我需要创建一个 `Cookie` 结构体，并展示如何将其添加到 `ResponseWriter` 的 `Header` 中。  这里需要模拟一个 `ResponseWriter`。

6. **涉及代码推理 (关于 `String()`):** `String()` 方法的实现涉及一些逻辑，比如如何根据 Cookie 的属性来构建字符串。 我需要解释 `String()` 方法如何根据 `Cookie` 结构体的不同字段生成相应的字符串，并考虑一些边缘情况，例如 `Domain` 的处理。 我注意到 `String()` 方法会根据不同的属性设置不同的键值对，例如 `Path=`, `Domain=`, `Expires=`, `Max-Age=` 等。

7. **命令行参数处理:** 我仔细检查了代码，没有发现直接处理命令行参数的部分。因此，我明确指出这一点。

8. **易犯错的点:**  我思考了在使用 Cookie 时常见的错误：
    * **`Set-Cookie` 格式错误:**  手动构建 `Set-Cookie` 字符串容易出错。
    * **Cookie 的作用域 (Path 和 Domain):**  初学者容易混淆 `Path` 和 `Domain` 的作用，导致 Cookie 无法按预期工作。
    * **SameSite 属性:**  不理解 `SameSite` 属性的含义和取值，可能导致跨站请求时 Cookie 被阻止发送。
    * **Secure 属性:** 没有在 HTTPS 环境下设置 `Secure` 属性可能导致安全问题。

9. **组织答案:** 最后，我将以上分析和例子组织成结构化的中文答案，包括功能列表、Go 语言功能实现说明、代码示例、代码推理、命令行参数处理和易犯错的点。  我确保使用了清晰的语言和格式，并添加了必要的解释和假设。

通过以上步骤，我能够从给定的 Go 源代码片段中提取出关键信息，理解其功能，并通过代码示例进行说明，最终生成了详细的中文解答。
这段代码是 Go 语言 `net/http` 包中用于处理 HTTP Cookie 的一部分。它定义了 `Cookie` 结构体和相关的解析、序列化和操作函数。

**主要功能列举：**

1. **定义 `Cookie` 结构体：**  该结构体用于表示一个 HTTP Cookie，包含了 Cookie 的名称、值、路径、域、过期时间、Max-Age、安全属性（Secure）、HttpOnly 属性、SameSite 属性等信息。

2. **解析 `Cookie` 请求头：** `ParseCookie(line string)` 函数用于解析 `Cookie` 请求头的值，返回一个 `Cookie` 指针的切片，表示请求中包含的所有 Cookie。

3. **解析 `Set-Cookie` 响应头：** `ParseSetCookie(line string)` 函数用于解析 `Set-Cookie` 响应头的值，返回一个 `Cookie` 指针，表示服务器设置的一个 Cookie。

4. **从 `Header` 中读取所有 `Set-Cookie`：** `readSetCookies(h Header)` 函数用于从 HTTP 头部 `Header` 中读取所有的 `Set-Cookie` 响应头，并解析成 `Cookie` 切片。

5. **设置 `Set-Cookie` 响应头：** `SetCookie(w ResponseWriter, cookie *Cookie)` 函数用于将一个 `Cookie` 对象添加到 HTTP 响应的头部中，作为 `Set-Cookie` 头部发送给客户端。

6. **将 `Cookie` 对象序列化为字符串：** `String() string` 方法用于将 `Cookie` 结构体序列化成符合 HTTP 规范的字符串格式，用于 `Cookie` 请求头或 `Set-Cookie` 响应头。

7. **验证 `Cookie` 对象的有效性：** `Valid() error` 方法用于检查 `Cookie` 结构体中的值是否符合规范，例如名称、过期时间、值等是否有效。

8. **从 `Header` 中读取所有 `Cookie` 请求头：** `readCookies(h Header, filter string)` 函数用于从 HTTP 头部 `Header` 中读取所有的 `Cookie` 请求头，并可以根据 `filter` 参数指定的 Cookie 名称进行过滤。

9. **提供辅助函数进行 Cookie 属性值的校验和清理：** 代码中包含 `validCookieDomain`、`validCookieExpires`、`isCookieDomainName`、`sanitizeCookieName`、`sanitizeCookieValue`、`sanitizeCookiePath` 等函数，用于校验和清理 Cookie 的域名、过期时间、名称、值和路径等属性。

**它是什么 Go 语言功能的实现？**

这段代码实现了 Go 语言中处理 HTTP Cookie 的核心功能。它使得 Go 编写的 HTTP 客户端和服务器能够方便地解析和生成符合 HTTP 规范的 Cookie。

**Go 代码举例说明：**

**场景：服务器接收到客户端的请求，并设置一个 Cookie 返回。**

```go
package main

import (
	"fmt"
	"net/http"
	"time"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// 创建一个 Cookie 对象
	cookie := &http.Cookie{
		Name:     "my_session",
		Value:    "abcdef123456",
		Path:     "/",
		Domain:   "example.com",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}

	// 设置 Cookie 到响应头
	http.SetCookie(w, cookie)

	fmt.Fprintln(w, "Cookie has been set!")
}

func main() {
	http.HandleFunc("/", handler)
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("ListenAndServe error:", err)
	}
}

// 假设的输入（客户端请求）：
// GET / HTTP/1.1
// Host: example.com

// 假设的输出（服务器响应）：
// HTTP/1.1 200 OK
// Set-Cookie: my_session=abcdef123456; Path=/; Domain=example.com; Expires=Tue, 17 Oct 2023 10:00:00 GMT; HttpOnly; Secure; SameSite=Strict
// Date: Mon, 16 Oct 2023 10:00:00 GMT
// Content-Type: text/plain; charset=utf-8
// Content-Length: 21
//
// Cookie has been set!
```

**场景：客户端发送请求，并在请求头中包含 Cookie。**

```go
package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
)

func main() {
	client := &http.Client{}
	req, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// 设置 Cookie 到请求头
	cookie := &http.Cookie{
		Name:  "my_session",
		Value: "abcdef123456",
	}
	req.AddCookie(cookie)

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// 打印请求头信息，可以看到 Cookie 信息
	reqDump, _ := httputil.DumpRequestOut(req, false)
	fmt.Printf("Request:\n%s\n", reqDump)

	fmt.Println("Response Status:", resp.Status)
}

// 假设的输入（程序执行）：无直接的用户输入

// 假设的输出（部分输出，显示 Cookie 信息）：
// Request:
// GET / HTTP/1.0
// Host: example.com
// Cookie: my_session=abcdef123456
//
// Response Status: 200 OK
```

**代码推理 (关于 `String()` 方法)：**

`String()` 方法负责将 `Cookie` 结构体转换为字符串。它会根据 `Cookie` 结构体中设置的字段，按照 HTTP Cookie 的格式拼接字符串。

**假设输入：**

```go
cookie := &http.Cookie{
	Name:     "test_cookie",
	Value:    "value123",
	Path:     "/path",
	Domain:   "sub.example.com",
	Expires:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	MaxAge:   3600,
	HttpOnly: true,
	Secure:   false,
	SameSite: http.SameSiteLaxMode,
}
```

**推理过程：**

`String()` 方法会按照以下步骤生成字符串：

1. **Name 和 Value:**  首先写入 `Name=Value`，即 `test_cookie=value123`。
2. **Path:** 如果 `Path` 不为空，则追加 `; Path=/path`。
3. **Domain:** 如果 `Domain` 有效，则追加 `; Domain=sub.example.com`（注意去除前导的 `.`）。
4. **Expires:** 如果 `Expires` 时间有效，则追加 `; Expires=Mon, 01 Jan 2024 00:00:00 GMT`（转换为 RFC1123 格式的 UTC 时间）。
5. **Max-Age:** 如果 `MaxAge` 大于 0，则追加 `; Max-Age=3600`。
6. **HttpOnly:** 如果 `HttpOnly` 为 `true`，则追加 `; HttpOnly`。
7. **Secure:** 如果 `Secure` 为 `true`，则追加 `; Secure`。
8. **SameSite:** 根据 `SameSite` 的值追加 `; SameSite=Lax`。

**假设输出：**

```
test_cookie=value123; Path=/path; Domain=sub.example.com; Expires=Mon, 01 Jan 2024 00:00:00 GMT; Max-Age=3600; HttpOnly; SameSite=Lax
```

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。HTTP Cookie 是在 HTTP 请求和响应头中进行传递的，与命令行参数无关。处理 HTTP 请求和响应通常发生在服务器端或客户端程序中，这些程序可能会通过其他方式（例如 `flag` 包）来处理命令行参数，但 Cookie 的处理逻辑与命令行参数是分离的。

**使用者易犯错的点：**

1. **`Set-Cookie` 头的格式错误：**  手动构建 `Set-Cookie` 字符串时，容易出现语法错误，导致 Cookie 设置失败或行为不符合预期。应该使用 `http.SetCookie` 函数或 `Cookie` 结构体的 `String()` 方法来生成。

   **错误示例：**

   ```go
   // 错误的设置 Cookie 方式
   w.Header().Set("Set-Cookie", "mycookie=value; path=/ user=test") // 缺少分隔符，user=test 会被当做额外的属性
   ```

2. **对 `Path` 和 `Domain` 属性的理解不足：**  `Path` 和 `Domain` 决定了 Cookie 的作用域。如果设置不当，Cookie 可能无法在预期的页面或域名下生效。

   * **`Path`：**  指定 Cookie 应该被发送的请求路径。例如，`Path=/admin` 表示 Cookie 只会在请求路径以 `/admin` 开头的请求中发送。
   * **`Domain`：**  指定 Cookie 对哪个域名有效。例如，`Domain=example.com` 表示 Cookie 对 `example.com` 及其子域名有效。如果不设置 `Domain`，则默认为设置 Cookie 的页面的主机名。

   **易错点：** 认为设置 `Domain=sub.example.com` 后，`example.com` 也能收到这个 Cookie，实际上需要显式设置为 `.example.com` 才能包含顶级域名。

3. **忽略 `HttpOnly` 和 `Secure` 属性：**

   * **`HttpOnly`：**  设置为 `true` 时，Cookie 只能通过 HTTP(S) 协议访问，JavaScript 无法访问，可以防止一些 XSS 攻击。忘记设置可能导致安全风险。
   * **`Secure`：**  设置为 `true` 时，Cookie 只能通过 HTTPS 连接发送，可以防止 Cookie 在不安全的连接中被窃取。在生产环境中，通常应该设置为 `true`。

4. **对 `Expires` 和 `MaxAge` 的混淆：**  这两个属性都用于设置 Cookie 的过期时间，但方式不同。

   * **`Expires`：**  指定一个具体的过期日期和时间。
   * **`MaxAge`：**  指定 Cookie 的最大生存时间（秒）。

   如果同时设置了 `Expires` 和 `MaxAge`，`MaxAge` 优先级更高。

   **易错点：**  设置了 `Expires` 但服务器或客户端的时钟不同步，可能导致 Cookie 过早或过晚过期。推荐使用 `MaxAge`。

5. **不理解 `SameSite` 属性的作用：**  `SameSite` 用于控制 Cookie 是否应该随跨站请求一起发送，可以防止 CSRF 攻击。如果不理解其 `Lax`、`Strict` 和 `None` 的含义，可能会导致 Cookie 在某些场景下无法正常工作。特别是设置 `SameSite=None` 时，必须同时设置 `Secure=true`。

希望以上解释能够帮助你理解这段 Go 代码的功能。

### 提示词
```
这是路径为go/src/net/http/cookie.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http/internal/ascii"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// A Cookie represents an HTTP cookie as sent in the Set-Cookie header of an
// HTTP response or the Cookie header of an HTTP request.
//
// See https://tools.ietf.org/html/rfc6265 for details.
type Cookie struct {
	Name   string
	Value  string
	Quoted bool // indicates whether the Value was originally quoted

	Path       string    // optional
	Domain     string    // optional
	Expires    time.Time // optional
	RawExpires string    // for reading cookies only

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge      int
	Secure      bool
	HttpOnly    bool
	SameSite    SameSite
	Partitioned bool
	Raw         string
	Unparsed    []string // Raw text of unparsed attribute-value pairs
}

// SameSite allows a server to define a cookie attribute making it impossible for
// the browser to send this cookie along with cross-site requests. The main
// goal is to mitigate the risk of cross-origin information leakage, and provide
// some protection against cross-site request forgery attacks.
//
// See https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00 for details.
type SameSite int

const (
	SameSiteDefaultMode SameSite = iota + 1
	SameSiteLaxMode
	SameSiteStrictMode
	SameSiteNoneMode
)

var (
	errBlankCookie           = errors.New("http: blank cookie")
	errEqualNotFoundInCookie = errors.New("http: '=' not found in cookie")
	errInvalidCookieName     = errors.New("http: invalid cookie name")
	errInvalidCookieValue    = errors.New("http: invalid cookie value")
)

// ParseCookie parses a Cookie header value and returns all the cookies
// which were set in it. Since the same cookie name can appear multiple times
// the returned Values can contain more than one value for a given key.
func ParseCookie(line string) ([]*Cookie, error) {
	parts := strings.Split(textproto.TrimString(line), ";")
	if len(parts) == 1 && parts[0] == "" {
		return nil, errBlankCookie
	}
	cookies := make([]*Cookie, 0, len(parts))
	for _, s := range parts {
		s = textproto.TrimString(s)
		name, value, found := strings.Cut(s, "=")
		if !found {
			return nil, errEqualNotFoundInCookie
		}
		if !isCookieNameValid(name) {
			return nil, errInvalidCookieName
		}
		value, quoted, found := parseCookieValue(value, true)
		if !found {
			return nil, errInvalidCookieValue
		}
		cookies = append(cookies, &Cookie{Name: name, Value: value, Quoted: quoted})
	}
	return cookies, nil
}

// ParseSetCookie parses a Set-Cookie header value and returns a cookie.
// It returns an error on syntax error.
func ParseSetCookie(line string) (*Cookie, error) {
	parts := strings.Split(textproto.TrimString(line), ";")
	if len(parts) == 1 && parts[0] == "" {
		return nil, errBlankCookie
	}
	parts[0] = textproto.TrimString(parts[0])
	name, value, ok := strings.Cut(parts[0], "=")
	if !ok {
		return nil, errEqualNotFoundInCookie
	}
	name = textproto.TrimString(name)
	if !isCookieNameValid(name) {
		return nil, errInvalidCookieName
	}
	value, quoted, ok := parseCookieValue(value, true)
	if !ok {
		return nil, errInvalidCookieValue
	}
	c := &Cookie{
		Name:   name,
		Value:  value,
		Quoted: quoted,
		Raw:    line,
	}
	for i := 1; i < len(parts); i++ {
		parts[i] = textproto.TrimString(parts[i])
		if len(parts[i]) == 0 {
			continue
		}

		attr, val, _ := strings.Cut(parts[i], "=")
		lowerAttr, isASCII := ascii.ToLower(attr)
		if !isASCII {
			continue
		}
		val, _, ok = parseCookieValue(val, false)
		if !ok {
			c.Unparsed = append(c.Unparsed, parts[i])
			continue
		}

		switch lowerAttr {
		case "samesite":
			lowerVal, ascii := ascii.ToLower(val)
			if !ascii {
				c.SameSite = SameSiteDefaultMode
				continue
			}
			switch lowerVal {
			case "lax":
				c.SameSite = SameSiteLaxMode
			case "strict":
				c.SameSite = SameSiteStrictMode
			case "none":
				c.SameSite = SameSiteNoneMode
			default:
				c.SameSite = SameSiteDefaultMode
			}
			continue
		case "secure":
			c.Secure = true
			continue
		case "httponly":
			c.HttpOnly = true
			continue
		case "domain":
			c.Domain = val
			continue
		case "max-age":
			secs, err := strconv.Atoi(val)
			if err != nil || secs != 0 && val[0] == '0' {
				break
			}
			if secs <= 0 {
				secs = -1
			}
			c.MaxAge = secs
			continue
		case "expires":
			c.RawExpires = val
			exptime, err := time.Parse(time.RFC1123, val)
			if err != nil {
				exptime, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", val)
				if err != nil {
					c.Expires = time.Time{}
					break
				}
			}
			c.Expires = exptime.UTC()
			continue
		case "path":
			c.Path = val
			continue
		case "partitioned":
			c.Partitioned = true
			continue
		}
		c.Unparsed = append(c.Unparsed, parts[i])
	}
	return c, nil
}

// readSetCookies parses all "Set-Cookie" values from
// the header h and returns the successfully parsed Cookies.
func readSetCookies(h Header) []*Cookie {
	cookieCount := len(h["Set-Cookie"])
	if cookieCount == 0 {
		return []*Cookie{}
	}
	cookies := make([]*Cookie, 0, cookieCount)
	for _, line := range h["Set-Cookie"] {
		if cookie, err := ParseSetCookie(line); err == nil {
			cookies = append(cookies, cookie)
		}
	}
	return cookies
}

// SetCookie adds a Set-Cookie header to the provided [ResponseWriter]'s headers.
// The provided cookie must have a valid Name. Invalid cookies may be
// silently dropped.
func SetCookie(w ResponseWriter, cookie *Cookie) {
	if v := cookie.String(); v != "" {
		w.Header().Add("Set-Cookie", v)
	}
}

// String returns the serialization of the cookie for use in a [Cookie]
// header (if only Name and Value are set) or a Set-Cookie response
// header (if other fields are set).
// If c is nil or c.Name is invalid, the empty string is returned.
func (c *Cookie) String() string {
	if c == nil || !isCookieNameValid(c.Name) {
		return ""
	}
	// extraCookieLength derived from typical length of cookie attributes
	// see RFC 6265 Sec 4.1.
	const extraCookieLength = 110
	var b strings.Builder
	b.Grow(len(c.Name) + len(c.Value) + len(c.Domain) + len(c.Path) + extraCookieLength)
	b.WriteString(c.Name)
	b.WriteRune('=')
	b.WriteString(sanitizeCookieValue(c.Value, c.Quoted))

	if len(c.Path) > 0 {
		b.WriteString("; Path=")
		b.WriteString(sanitizeCookiePath(c.Path))
	}
	if len(c.Domain) > 0 {
		if validCookieDomain(c.Domain) {
			// A c.Domain containing illegal characters is not
			// sanitized but simply dropped which turns the cookie
			// into a host-only cookie. A leading dot is okay
			// but won't be sent.
			d := c.Domain
			if d[0] == '.' {
				d = d[1:]
			}
			b.WriteString("; Domain=")
			b.WriteString(d)
		} else {
			log.Printf("net/http: invalid Cookie.Domain %q; dropping domain attribute", c.Domain)
		}
	}
	var buf [len(TimeFormat)]byte
	if validCookieExpires(c.Expires) {
		b.WriteString("; Expires=")
		b.Write(c.Expires.UTC().AppendFormat(buf[:0], TimeFormat))
	}
	if c.MaxAge > 0 {
		b.WriteString("; Max-Age=")
		b.Write(strconv.AppendInt(buf[:0], int64(c.MaxAge), 10))
	} else if c.MaxAge < 0 {
		b.WriteString("; Max-Age=0")
	}
	if c.HttpOnly {
		b.WriteString("; HttpOnly")
	}
	if c.Secure {
		b.WriteString("; Secure")
	}
	switch c.SameSite {
	case SameSiteDefaultMode:
		// Skip, default mode is obtained by not emitting the attribute.
	case SameSiteNoneMode:
		b.WriteString("; SameSite=None")
	case SameSiteLaxMode:
		b.WriteString("; SameSite=Lax")
	case SameSiteStrictMode:
		b.WriteString("; SameSite=Strict")
	}
	if c.Partitioned {
		b.WriteString("; Partitioned")
	}
	return b.String()
}

// Valid reports whether the cookie is valid.
func (c *Cookie) Valid() error {
	if c == nil {
		return errors.New("http: nil Cookie")
	}
	if !isCookieNameValid(c.Name) {
		return errors.New("http: invalid Cookie.Name")
	}
	if !c.Expires.IsZero() && !validCookieExpires(c.Expires) {
		return errors.New("http: invalid Cookie.Expires")
	}
	for i := 0; i < len(c.Value); i++ {
		if !validCookieValueByte(c.Value[i]) {
			return fmt.Errorf("http: invalid byte %q in Cookie.Value", c.Value[i])
		}
	}
	if len(c.Path) > 0 {
		for i := 0; i < len(c.Path); i++ {
			if !validCookiePathByte(c.Path[i]) {
				return fmt.Errorf("http: invalid byte %q in Cookie.Path", c.Path[i])
			}
		}
	}
	if len(c.Domain) > 0 {
		if !validCookieDomain(c.Domain) {
			return errors.New("http: invalid Cookie.Domain")
		}
	}
	if c.Partitioned {
		if !c.Secure {
			return errors.New("http: partitioned cookies must be set with Secure")
		}
	}
	return nil
}

// readCookies parses all "Cookie" values from the header h and
// returns the successfully parsed Cookies.
//
// if filter isn't empty, only cookies of that name are returned.
func readCookies(h Header, filter string) []*Cookie {
	lines := h["Cookie"]
	if len(lines) == 0 {
		return []*Cookie{}
	}

	cookies := make([]*Cookie, 0, len(lines)+strings.Count(lines[0], ";"))
	for _, line := range lines {
		line = textproto.TrimString(line)

		var part string
		for len(line) > 0 { // continue since we have rest
			part, line, _ = strings.Cut(line, ";")
			part = textproto.TrimString(part)
			if part == "" {
				continue
			}
			name, val, _ := strings.Cut(part, "=")
			name = textproto.TrimString(name)
			if !isCookieNameValid(name) {
				continue
			}
			if filter != "" && filter != name {
				continue
			}
			val, quoted, ok := parseCookieValue(val, true)
			if !ok {
				continue
			}
			cookies = append(cookies, &Cookie{Name: name, Value: val, Quoted: quoted})
		}
	}
	return cookies
}

// validCookieDomain reports whether v is a valid cookie domain-value.
func validCookieDomain(v string) bool {
	if isCookieDomainName(v) {
		return true
	}
	if net.ParseIP(v) != nil && !strings.Contains(v, ":") {
		return true
	}
	return false
}

// validCookieExpires reports whether v is a valid cookie expires-value.
func validCookieExpires(t time.Time) bool {
	// IETF RFC 6265 Section 5.1.1.5, the year must not be less than 1601
	return t.Year() >= 1601
}

// isCookieDomainName reports whether s is a valid domain name or a valid
// domain name with a leading dot '.'.  It is almost a direct copy of
// package net's isDomainName.
func isCookieDomainName(s string) bool {
	if len(s) == 0 {
		return false
	}
	if len(s) > 255 {
		return false
	}

	if s[0] == '.' {
		// A cookie a domain attribute may start with a leading dot.
		s = s[1:]
	}
	last := byte('.')
	ok := false // Ok once we've seen a letter.
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			// No '_' allowed here (in contrast to package net).
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return ok
}

var cookieNameSanitizer = strings.NewReplacer("\n", "-", "\r", "-")

func sanitizeCookieName(n string) string {
	return cookieNameSanitizer.Replace(n)
}

// sanitizeCookieValue produces a suitable cookie-value from v.
// It receives a quoted bool indicating whether the value was originally
// quoted.
// https://tools.ietf.org/html/rfc6265#section-4.1.1
//
//	cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
//	cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
//	          ; US-ASCII characters excluding CTLs,
//	          ; whitespace DQUOTE, comma, semicolon,
//	          ; and backslash
//
// We loosen this as spaces and commas are common in cookie values
// thus we produce a quoted cookie-value if v contains commas or spaces.
// See https://golang.org/issue/7243 for the discussion.
func sanitizeCookieValue(v string, quoted bool) string {
	v = sanitizeOrWarn("Cookie.Value", validCookieValueByte, v)
	if len(v) == 0 {
		return v
	}
	if strings.ContainsAny(v, " ,") || quoted {
		return `"` + v + `"`
	}
	return v
}

func validCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

// path-av           = "Path=" path-value
// path-value        = <any CHAR except CTLs or ";">
func sanitizeCookiePath(v string) string {
	return sanitizeOrWarn("Cookie.Path", validCookiePathByte, v)
}

func validCookiePathByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != ';'
}

func sanitizeOrWarn(fieldName string, valid func(byte) bool, v string) string {
	ok := true
	for i := 0; i < len(v); i++ {
		if valid(v[i]) {
			continue
		}
		log.Printf("net/http: invalid byte %q in %s; dropping invalid bytes", v[i], fieldName)
		ok = false
		break
	}
	if ok {
		return v
	}
	buf := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		if b := v[i]; valid(b) {
			buf = append(buf, b)
		}
	}
	return string(buf)
}

// parseCookieValue parses a cookie value according to RFC 6265.
// If allowDoubleQuote is true, parseCookieValue will consider that it
// is parsing the cookie-value;
// otherwise, it will consider that it is parsing a cookie-av value
// (cookie attribute-value).
//
// It returns the parsed cookie value, a boolean indicating whether the
// parsing was successful, and a boolean indicating whether the parsed
// value was enclosed in double quotes.
func parseCookieValue(raw string, allowDoubleQuote bool) (value string, quoted, ok bool) {
	// Strip the quotes, if present.
	if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
		quoted = true
	}
	for i := 0; i < len(raw); i++ {
		if !validCookieValueByte(raw[i]) {
			return "", quoted, false
		}
	}
	return raw, quoted, true
}

func isCookieNameValid(raw string) bool {
	if raw == "" {
		return false
	}
	return strings.IndexFunc(raw, isNotToken) < 0
}
```