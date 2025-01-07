Response:
The user has provided a snippet of Go code from `net/http/request.go` and asked for a summary of its functionalities, assuming this is the second part of a two-part question.

Based on the provided code, I can identify the following functionalities:

1. **Basic Authentication Handling:**  Functions to parse and set Basic Authentication headers.
2. **Request Line Parsing:** A function to parse the first line of an HTTP request.
3. **Request Reading:**  Functions to read and parse an incoming HTTP request from a `bufio.Reader`.
4. **Request Body Size Limiting:** A mechanism to limit the size of the incoming request body to prevent abuse.
5. **Form Data Parsing:** Functions to parse form data from the request body (both `application/x-www-form-urlencoded` and `multipart/form-data`).
6. **Form Value Retrieval:** Functions to retrieve specific values from the parsed form data.
7. **Path Value Retrieval/Setting:**  Functions related to retrieving and setting values from path wildcards, likely used with a `ServeMux`.
8. **Connection Management Hints:** Functions to determine if the client expects a "100-continue" response or wants to keep the connection alive or close it.
9. **Request Body Handling:** Functions to close the request body and check if a request is replayable.
10. **Outgoing Request Length:** A function to determine the content length of an outgoing request.
11. **HTTP Version Requirement Check:** A function to check if the request requires an HTTP/1 connection.

Since this is the second part of the question, I need to summarize the functionalities presented in this specific snippet. I will focus on the user-facing APIs and the core functionalities implemented here.
这是 `go/src/net/http/request.go` 文件的一部分，主要负责处理 HTTP 请求的解析、认证和数据提取。 总结一下这部分代码的功能如下：

1. **处理 HTTP 基本认证 (Basic Authentication):**
   - 提供了 `BasicAuth` 函数来从请求头中解析出用户名和密码。
   - 提供了 `parseBasicAuth` 函数，这是 `BasicAuth` 的底层实现，用于解析 "Authorization" 头部的 "Basic" 认证信息。
   - 提供了 `SetBasicAuth` 函数，用于在 `Request` 对象的头部设置 "Authorization" 字段，方便发起带有基本认证的请求。

2. **解析 HTTP 请求行 (Request Line):**
   - 提供了 `parseRequestLine` 函数，用于解析 HTTP 请求的第一行，例如 "GET /foo HTTP/1.1"，提取出请求方法 (method)、请求 URI (requestURI) 和协议版本 (proto)。

3. **读取和解析 HTTP 请求:**
   - 提供了 `ReadRequest` 函数，这是一个底层函数，用于从 `bufio.Reader` 中读取并解析完整的 HTTP 请求。它处理请求行、头部等信息。
   - 内部使用了 `readRequest` 函数作为 `ReadRequest` 的实际实现。

4. **限制请求体大小:**
   - 提供了 `MaxBytesReader` 函数，用于创建一个 `io.ReadCloser`，它可以限制读取的请求体大小。这有助于防止客户端发送过大的请求，浪费服务器资源。
   - 定义了 `MaxBytesError` 类型，当读取超过限制时返回此错误。

5. **解析表单数据 (Form Data):**
   - 提供了 `parsePostForm` 函数，用于解析 POST 请求中的 `application/x-www-form-urlencoded` 类型的数据。
   - 提供了 `ParseForm` 函数，它会解析 URL 中的查询参数，并且对于 POST、PUT、PATCH 请求，还会解析请求体中的表单数据（包括 `application/x-www-form-urlencoded` 和 `multipart/form-data`，后者会调用 `ParseMultipartForm`）。请求体中的参数优先级高于 URL 查询参数。

6. **解析 multipart/form-data 数据:**
   - 提供了 `ParseMultipartForm` 函数，用于解析 `multipart/form-data` 类型的请求体，用于处理文件上传等场景。它可以设置最大内存限制，超过限制的文件会存储在磁盘上。

7. **获取表单值:**
   - 提供了 `FormValue` 函数，用于获取指定键的表单值，它会考虑请求体和 URL 查询参数中的值。
   - 提供了 `PostFormValue` 函数，专门用于获取 POST、PUT、PATCH 请求体中的表单值，忽略 URL 查询参数。
   - 提供了 `FormFile` 函数，用于获取 `multipart/form-data` 中上传的文件。

8. **处理路径参数 (Path Values):**
   - 提供了 `PathValue` 函数，用于获取在 `ServeMux` 匹配请求时提取的路径通配符的值。
   - 提供了 `SetPathValue` 函数，用于设置路径参数的值。

9. **判断连接状态:**
   - 提供了 `expectsContinue` 函数，判断请求头中是否包含 "Expect: 100-continue"。
   - 提供了 `wantsHttp10KeepAlive` 函数，判断是否为 HTTP/1.0 请求并希望保持连接。
   - 提供了 `wantsClose` 函数，判断请求是否希望关闭连接。

10. **请求体管理:**
    - 提供了 `closeBody` 函数，用于关闭请求体。
    - 提供了 `isReplayable` 函数，判断请求是否可以被重放（通常对于 GET、HEAD 等幂等方法）。

11. **获取出站请求长度:**
    - 提供了 `outgoingLength` 函数，用于获取出站请求的 Content-Length。

12. **判断请求方法是否通常没有请求体:**
    - 提供了 `requestMethodUsuallyLacksBody` 函数，用于判断请求方法（如 GET、HEAD）是否通常不包含请求体。

13. **判断是否需要 HTTP/1 协议:**
    - 提供了 `requiresHTTP1` 函数，判断请求是否因为 Upgrade 头部 (例如 WebSocket) 而必须使用 HTTP/1。

**功能归纳:**

这部分代码主要负责 **解析和处理 HTTP 请求的各个方面**，包括请求头、请求行、请求体以及相关的认证信息和表单数据。它提供了用于服务器端接收和处理请求，以及客户端构造请求的基础功能。  核心目标是将原始的字节流转换为结构化的 `Request` 对象，方便后续的处理和逻辑实现。

Prompt: 
```
这是路径为go/src/net/http/request.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", "", false
	}
	return parseBasicAuth(auth)
}

// parseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
//
// parseBasicAuth should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/sagernet/sing
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname parseBasicAuth
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !ascii.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	cs := string(c)
	username, password, ok = strings.Cut(cs, ":")
	if !ok {
		return "", "", false
	}
	return username, password, true
}

// SetBasicAuth sets the request's Authorization header to use HTTP
// Basic Authentication with the provided username and password.
//
// With HTTP Basic Authentication the provided username and password
// are not encrypted. It should generally only be used in an HTTPS
// request.
//
// The username may not contain a colon. Some protocols may impose
// additional requirements on pre-escaping the username and
// password. For instance, when used with OAuth2, both arguments must
// be URL encoded first with [url.QueryEscape].
func (r *Request) SetBasicAuth(username, password string) {
	r.Header.Set("Authorization", "Basic "+basicAuth(username, password))
}

// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	method, rest, ok1 := strings.Cut(line, " ")
	requestURI, proto, ok2 := strings.Cut(rest, " ")
	if !ok1 || !ok2 {
		return "", "", "", false
	}
	return method, requestURI, proto, true
}

var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}

// ReadRequest reads and parses an incoming request from b.
//
// ReadRequest is a low-level function and should only be used for
// specialized applications; most code should use the [Server] to read
// requests and handle them via the [Handler] interface. ReadRequest
// only supports HTTP/1.x requests. For HTTP/2, use golang.org/x/net/http2.
func ReadRequest(b *bufio.Reader) (*Request, error) {
	req, err := readRequest(b)
	if err != nil {
		return nil, err
	}

	delete(req.Header, "Host")
	return req, err
}

// readRequest should be an internal detail,
// but widely used packages access it using linkname.
// Notable members of the hall of shame include:
//   - github.com/sagernet/sing
//   - github.com/v2fly/v2ray-core/v4
//   - github.com/v2fly/v2ray-core/v5
//
// Do not remove or change the type signature.
// See go.dev/issue/67401.
//
//go:linkname readRequest
func readRequest(b *bufio.Reader) (req *Request, err error) {
	tp := newTextprotoReader(b)
	defer putTextprotoReader(tp)

	req = new(Request)

	// First line: GET /index.html HTTP/1.0
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return nil, err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	var ok bool
	req.Method, req.RequestURI, req.Proto, ok = parseRequestLine(s)
	if !ok {
		return nil, badStringError("malformed HTTP request", s)
	}
	if !validMethod(req.Method) {
		return nil, badStringError("invalid method", req.Method)
	}
	rawurl := req.RequestURI
	if req.ProtoMajor, req.ProtoMinor, ok = ParseHTTPVersion(req.Proto); !ok {
		return nil, badStringError("malformed HTTP version", req.Proto)
	}

	// CONNECT requests are used two different ways, and neither uses a full URL:
	// The standard use is to tunnel HTTPS through an HTTP proxy.
	// It looks like "CONNECT www.google.com:443 HTTP/1.1", and the parameter is
	// just the authority section of a URL. This information should go in req.URL.Host.
	//
	// The net/rpc package also uses CONNECT, but there the parameter is a path
	// that starts with a slash. It can be parsed with the regular URL parser,
	// and the path will end up in req.URL.Path, where it needs to be in order for
	// RPC to work.
	justAuthority := req.Method == "CONNECT" && !strings.HasPrefix(rawurl, "/")
	if justAuthority {
		rawurl = "http://" + rawurl
	}

	if req.URL, err = url.ParseRequestURI(rawurl); err != nil {
		return nil, err
	}

	if justAuthority {
		// Strip the bogus "http://" back off.
		req.URL.Scheme = ""
	}

	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, err
	}
	req.Header = Header(mimeHeader)
	if len(req.Header["Host"]) > 1 {
		return nil, fmt.Errorf("too many Host headers")
	}

	// RFC 7230, section 5.3: Must treat
	//	GET /index.html HTTP/1.1
	//	Host: www.google.com
	// and
	//	GET http://www.google.com/index.html HTTP/1.1
	//	Host: doesntmatter
	// the same. In the second case, any Host line is ignored.
	req.Host = req.URL.Host
	if req.Host == "" {
		req.Host = req.Header.get("Host")
	}

	fixPragmaCacheControl(req.Header)

	req.Close = shouldClose(req.ProtoMajor, req.ProtoMinor, req.Header, false)

	err = readTransfer(req, b)
	if err != nil {
		return nil, err
	}

	if req.isH2Upgrade() {
		// Because it's neither chunked, nor declared:
		req.ContentLength = -1

		// We want to give handlers a chance to hijack the
		// connection, but we need to prevent the Server from
		// dealing with the connection further if it's not
		// hijacked. Set Close to ensure that:
		req.Close = true
	}
	return req, nil
}

// MaxBytesReader is similar to [io.LimitReader] but is intended for
// limiting the size of incoming request bodies. In contrast to
// io.LimitReader, MaxBytesReader's result is a ReadCloser, returns a
// non-nil error of type [*MaxBytesError] for a Read beyond the limit,
// and closes the underlying reader when its Close method is called.
//
// MaxBytesReader prevents clients from accidentally or maliciously
// sending a large request and wasting server resources. If possible,
// it tells the [ResponseWriter] to close the connection after the limit
// has been reached.
func MaxBytesReader(w ResponseWriter, r io.ReadCloser, n int64) io.ReadCloser {
	if n < 0 { // Treat negative limits as equivalent to 0.
		n = 0
	}
	return &maxBytesReader{w: w, r: r, i: n, n: n}
}

// MaxBytesError is returned by [MaxBytesReader] when its read limit is exceeded.
type MaxBytesError struct {
	Limit int64
}

func (e *MaxBytesError) Error() string {
	// Due to Hyrum's law, this text cannot be changed.
	return "http: request body too large"
}

type maxBytesReader struct {
	w   ResponseWriter
	r   io.ReadCloser // underlying reader
	i   int64         // max bytes initially, for MaxBytesError
	n   int64         // max bytes remaining
	err error         // sticky error
}

func (l *maxBytesReader) Read(p []byte) (n int, err error) {
	if l.err != nil {
		return 0, l.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	// If they asked for a 32KB byte read but only 5 bytes are
	// remaining, no need to read 32KB. 6 bytes will answer the
	// question of the whether we hit the limit or go past it.
	// 0 < len(p) < 2^63
	if int64(len(p))-1 > l.n {
		p = p[:l.n+1]
	}
	n, err = l.r.Read(p)

	if int64(n) <= l.n {
		l.n -= int64(n)
		l.err = err
		return n, err
	}

	n = int(l.n)
	l.n = 0

	// The server code and client code both use
	// maxBytesReader. This "requestTooLarge" check is
	// only used by the server code. To prevent binaries
	// which only using the HTTP Client code (such as
	// cmd/go) from also linking in the HTTP server, don't
	// use a static type assertion to the server
	// "*response" type. Check this interface instead:
	type requestTooLarger interface {
		requestTooLarge()
	}
	if res, ok := l.w.(requestTooLarger); ok {
		res.requestTooLarge()
	}
	l.err = &MaxBytesError{l.i}
	return n, l.err
}

func (l *maxBytesReader) Close() error {
	return l.r.Close()
}

func copyValues(dst, src url.Values) {
	for k, vs := range src {
		dst[k] = append(dst[k], vs...)
	}
}

func parsePostForm(r *Request) (vs url.Values, err error) {
	if r.Body == nil {
		err = errors.New("missing form body")
		return
	}
	ct := r.Header.Get("Content-Type")
	// RFC 7231, section 3.1.1.5 - empty type
	//   MAY be treated as application/octet-stream
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, _, err = mime.ParseMediaType(ct)
	switch {
	case ct == "application/x-www-form-urlencoded":
		var reader io.Reader = r.Body
		maxFormSize := int64(1<<63 - 1)
		if _, ok := r.Body.(*maxBytesReader); !ok {
			maxFormSize = int64(10 << 20) // 10 MB is a lot of text.
			reader = io.LimitReader(r.Body, maxFormSize+1)
		}
		b, e := io.ReadAll(reader)
		if e != nil {
			if err == nil {
				err = e
			}
			break
		}
		if int64(len(b)) > maxFormSize {
			err = errors.New("http: POST too large")
			return
		}
		vs, e = url.ParseQuery(string(b))
		if err == nil {
			err = e
		}
	case ct == "multipart/form-data":
		// handled by ParseMultipartForm (which is calling us, or should be)
		// TODO(bradfitz): there are too many possible
		// orders to call too many functions here.
		// Clean this up and write more tests.
		// request_test.go contains the start of this,
		// in TestParseMultipartFormOrder and others.
	}
	return
}

// ParseForm populates r.Form and r.PostForm.
//
// For all requests, ParseForm parses the raw query from the URL and updates
// r.Form.
//
// For POST, PUT, and PATCH requests, it also reads the request body, parses it
// as a form and puts the results into both r.PostForm and r.Form. Request body
// parameters take precedence over URL query string values in r.Form.
//
// If the request Body's size has not already been limited by [MaxBytesReader],
// the size is capped at 10MB.
//
// For other HTTP methods, or when the Content-Type is not
// application/x-www-form-urlencoded, the request Body is not read, and
// r.PostForm is initialized to a non-nil, empty value.
//
// [Request.ParseMultipartForm] calls ParseForm automatically.
// ParseForm is idempotent.
func (r *Request) ParseForm() error {
	var err error
	if r.PostForm == nil {
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			r.PostForm, err = parsePostForm(r)
		}
		if r.PostForm == nil {
			r.PostForm = make(url.Values)
		}
	}
	if r.Form == nil {
		if len(r.PostForm) > 0 {
			r.Form = make(url.Values)
			copyValues(r.Form, r.PostForm)
		}
		var newValues url.Values
		if r.URL != nil {
			var e error
			newValues, e = url.ParseQuery(r.URL.RawQuery)
			if err == nil {
				err = e
			}
		}
		if newValues == nil {
			newValues = make(url.Values)
		}
		if r.Form == nil {
			r.Form = newValues
		} else {
			copyValues(r.Form, newValues)
		}
	}
	return err
}

// ParseMultipartForm parses a request body as multipart/form-data.
// The whole request body is parsed and up to a total of maxMemory bytes of
// its file parts are stored in memory, with the remainder stored on
// disk in temporary files.
// ParseMultipartForm calls [Request.ParseForm] if necessary.
// If ParseForm returns an error, ParseMultipartForm returns it but also
// continues parsing the request body.
// After one call to ParseMultipartForm, subsequent calls have no effect.
func (r *Request) ParseMultipartForm(maxMemory int64) error {
	if r.MultipartForm == multipartByReader {
		return errors.New("http: multipart handled by MultipartReader")
	}
	var parseFormErr error
	if r.Form == nil {
		// Let errors in ParseForm fall through, and just
		// return it at the end.
		parseFormErr = r.ParseForm()
	}
	if r.MultipartForm != nil {
		return nil
	}

	mr, err := r.multipartReader(false)
	if err != nil {
		return err
	}

	f, err := mr.ReadForm(maxMemory)
	if err != nil {
		return err
	}

	if r.PostForm == nil {
		r.PostForm = make(url.Values)
	}
	for k, v := range f.Value {
		r.Form[k] = append(r.Form[k], v...)
		// r.PostForm should also be populated. See Issue 9305.
		r.PostForm[k] = append(r.PostForm[k], v...)
	}

	r.MultipartForm = f

	return parseFormErr
}

// FormValue returns the first value for the named component of the query.
// The precedence order:
//  1. application/x-www-form-urlencoded form body (POST, PUT, PATCH only)
//  2. query parameters (always)
//  3. multipart/form-data form body (always)
//
// FormValue calls [Request.ParseMultipartForm] and [Request.ParseForm]
// if necessary and ignores any errors returned by these functions.
// If key is not present, FormValue returns the empty string.
// To access multiple values of the same key, call ParseForm and
// then inspect [Request.Form] directly.
func (r *Request) FormValue(key string) string {
	if r.Form == nil {
		r.ParseMultipartForm(defaultMaxMemory)
	}
	if vs := r.Form[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// PostFormValue returns the first value for the named component of the POST,
// PUT, or PATCH request body. URL query parameters are ignored.
// PostFormValue calls [Request.ParseMultipartForm] and [Request.ParseForm] if necessary and ignores
// any errors returned by these functions.
// If key is not present, PostFormValue returns the empty string.
func (r *Request) PostFormValue(key string) string {
	if r.PostForm == nil {
		r.ParseMultipartForm(defaultMaxMemory)
	}
	if vs := r.PostForm[key]; len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// FormFile returns the first file for the provided form key.
// FormFile calls [Request.ParseMultipartForm] and [Request.ParseForm] if necessary.
func (r *Request) FormFile(key string) (multipart.File, *multipart.FileHeader, error) {
	if r.MultipartForm == multipartByReader {
		return nil, nil, errors.New("http: multipart handled by MultipartReader")
	}
	if r.MultipartForm == nil {
		err := r.ParseMultipartForm(defaultMaxMemory)
		if err != nil {
			return nil, nil, err
		}
	}
	if r.MultipartForm != nil && r.MultipartForm.File != nil {
		if fhs := r.MultipartForm.File[key]; len(fhs) > 0 {
			f, err := fhs[0].Open()
			return f, fhs[0], err
		}
	}
	return nil, nil, ErrMissingFile
}

// PathValue returns the value for the named path wildcard in the [ServeMux] pattern
// that matched the request.
// It returns the empty string if the request was not matched against a pattern
// or there is no such wildcard in the pattern.
func (r *Request) PathValue(name string) string {
	if i := r.patIndex(name); i >= 0 {
		return r.matches[i]
	}
	return r.otherValues[name]
}

// SetPathValue sets name to value, so that subsequent calls to r.PathValue(name)
// return value.
func (r *Request) SetPathValue(name, value string) {
	if i := r.patIndex(name); i >= 0 {
		r.matches[i] = value
	} else {
		if r.otherValues == nil {
			r.otherValues = map[string]string{}
		}
		r.otherValues[name] = value
	}
}

// patIndex returns the index of name in the list of named wildcards of the
// request's pattern, or -1 if there is no such name.
func (r *Request) patIndex(name string) int {
	// The linear search seems expensive compared to a map, but just creating the map
	// takes a lot of time, and most patterns will just have a couple of wildcards.
	if r.pat == nil {
		return -1
	}
	i := 0
	for _, seg := range r.pat.segments {
		if seg.wild && seg.s != "" {
			if name == seg.s {
				return i
			}
			i++
		}
	}
	return -1
}

func (r *Request) expectsContinue() bool {
	return hasToken(r.Header.get("Expect"), "100-continue")
}

func (r *Request) wantsHttp10KeepAlive() bool {
	if r.ProtoMajor != 1 || r.ProtoMinor != 0 {
		return false
	}
	return hasToken(r.Header.get("Connection"), "keep-alive")
}

func (r *Request) wantsClose() bool {
	if r.Close {
		return true
	}
	return hasToken(r.Header.get("Connection"), "close")
}

func (r *Request) closeBody() error {
	if r.Body == nil {
		return nil
	}
	return r.Body.Close()
}

func (r *Request) isReplayable() bool {
	if r.Body == nil || r.Body == NoBody || r.GetBody != nil {
		switch valueOrDefault(r.Method, "GET") {
		case "GET", "HEAD", "OPTIONS", "TRACE":
			return true
		}
		// The Idempotency-Key, while non-standard, is widely used to
		// mean a POST or other request is idempotent. See
		// https://golang.org/issue/19943#issuecomment-421092421
		if r.Header.has("Idempotency-Key") || r.Header.has("X-Idempotency-Key") {
			return true
		}
	}
	return false
}

// outgoingLength reports the Content-Length of this outgoing (Client) request.
// It maps 0 into -1 (unknown) when the Body is non-nil.
func (r *Request) outgoingLength() int64 {
	if r.Body == nil || r.Body == NoBody {
		return 0
	}
	if r.ContentLength != 0 {
		return r.ContentLength
	}
	return -1
}

// requestMethodUsuallyLacksBody reports whether the given request
// method is one that typically does not involve a request body.
// This is used by the Transport (via
// transferWriter.shouldSendChunkedRequestBody) to determine whether
// we try to test-read a byte from a non-nil Request.Body when
// Request.outgoingLength() returns -1. See the comments in
// shouldSendChunkedRequestBody.
func requestMethodUsuallyLacksBody(method string) bool {
	switch method {
	case "GET", "HEAD", "DELETE", "OPTIONS", "PROPFIND", "SEARCH":
		return true
	}
	return false
}

// requiresHTTP1 reports whether this request requires being sent on
// an HTTP/1 connection.
func (r *Request) requiresHTTP1() bool {
	return hasToken(r.Header.Get("Connection"), "upgrade") &&
		ascii.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

"""




```