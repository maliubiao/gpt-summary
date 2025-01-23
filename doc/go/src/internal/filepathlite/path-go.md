Response:
Let's break down the thought process for analyzing this Go code snippet and generating the desired answer.

1. **Understanding the Request:** The core request is to understand the functionality of the provided Go code, which is explicitly stated to be a subset of `path/filepath`. Key points to address are the functions it implements, examples of their use, potential error points, and an overall understanding of the purpose of this "lite" version.

2. **Initial Scan and Keyword Identification:** I'd start by quickly reading through the code, looking for key terms and function names that hint at their purpose. I see:

    * `package filepathlite`: This immediately tells me it's a lightweight version of the standard `path/filepath` package.
    * `// Clean is filepath.Clean.` (and similar comments for other functions): This is a huge clue, explicitly linking the functions to their counterparts in the standard library. This saves a lot of guesswork.
    * Function names like `Clean`, `IsLocal`, `Localize`, `ToSlash`, `FromSlash`, `Split`, `Ext`, `Base`, `Dir`, `VolumeName`, `VolumeNameLen`: These are standard file path manipulation functions.
    * The `lazybuf` struct: This suggests an optimization for string manipulation, likely to avoid unnecessary allocations.
    * The `errInvalidPath` variable:  Indicates error handling.

3. **Function-by-Function Analysis:**  I would then go through each exported function, noting its purpose based on the comments and its implementation.

    * **`Clean(path string) string`**: The comment directly states it's `filepath.Clean`. I know `filepath.Clean` cleans a path by removing redundant separators, `.` and `..` components. I need an example of this.
    * **`IsLocal(path string) bool`**:  Again, the comment is direct. `filepath.IsLocal` checks if a path is relative and doesn't contain `..` that would go outside the current directory. I'd look at the `unixIsLocal` implementation to understand the logic. An example is needed.
    * **`Localize(path string) (string, error)`**:  The comment indicates it's `filepath.Localize`. This function is less common and its purpose isn't immediately obvious from the name alone. The code checks `fs.ValidPath`, suggesting it's about validating path syntax. An example is needed, including a case that returns an error.
    * **`ToSlash(path string) string`**:  The comment links it to `filepath.ToSlash`. This converts path separators to forward slashes. An example is straightforward.
    * **`FromSlash(path string) string`**:  The comment links it to `filepath.FromSlash`. This converts forward slashes to the system's path separator. An example is needed.
    * **`Split(path string) (dir, file string)`**: The comment links it to `filepath.Split`. This splits a path into its directory and file components. An example is needed.
    * **`Ext(path string) string`**: The comment links it to `filepath.Ext`. This extracts the file extension. An example is needed.
    * **`Base(path string) string`**: The comment links it to `filepath.Base`. This extracts the last element of a path. An example is needed, especially considering the edge case of an empty path.
    * **`Dir(path string) string`**: The comment links it to `filepath.Dir`. This extracts the directory part of a path. An example is needed.
    * **`VolumeName(path string) string`**: The comment links it to `filepath.VolumeName`. This extracts the volume name (drive letter on Windows, empty elsewhere). An example is needed, especially for Windows.
    * **`VolumeNameLen(path string) int`**: The comment links it to `filepath.VolumeNameLen`. This returns the length of the volume name. An example is needed, again focusing on Windows.

4. **Inferring the Overall Purpose:** Based on the function names and the package description, it's clear that this package provides a subset of the `path/filepath` functionality. The comment "only using packages which may be imported by 'os'" explains *why* this exists. It's for situations where you need basic path manipulation but want to minimize dependencies, specifically avoiding importing parts of the standard library that `os` doesn't depend on.

5. **Code Reasoning and Examples:** For each function, I need to create clear examples. This involves:

    * **Choosing illustrative inputs:**  Select paths that demonstrate the function's behavior, including edge cases (empty strings, paths with multiple separators, paths with `.` and `..`).
    * **Predicting the output:** Based on my understanding of the standard `path/filepath` package, I can predict the output.
    * **Writing the Go code:**  Structure the examples using `fmt.Println` to clearly show the input and output.

6. **Command Line Arguments:** This section isn't relevant because the provided code doesn't directly interact with command-line arguments. The functions operate on string inputs.

7. **Common Mistakes:** I need to think about potential pitfalls users might encounter. For example, misunderstanding how `Clean` handles `..`, or assuming `IsLocal` behaves differently than it does. Focusing on the core functionality of each function helps identify these.

8. **Structuring the Answer:**  Finally, I need to organize the information in a clear and readable format, following the instructions in the prompt (using Chinese). This includes:

    * Listing the functions and their descriptions.
    * Providing Go code examples with input and output.
    * Explaining the purpose of the package.
    * Addressing potential mistakes.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe `Localize` does something with locales. **Correction:** The `fs.ValidPath` check suggests it's about validating the *syntax* of the path, not its localization.
* **Initial thought:**  Should I explain the `lazybuf` implementation in detail? **Correction:** The request focuses on the *functionality* of the exported functions. The internal implementation details of `lazybuf` are less important for understanding how to *use* the package. Briefly mentioning it as an optimization is sufficient.
* **Ensuring clarity in examples:** Double-check that the input paths and expected outputs in the examples are clear and directly illustrate the function's behavior. For example, for `Clean`, include cases with redundant slashes, `.`, and `..`.

By following these steps, combining careful reading of the code with prior knowledge of the `path/filepath` package, and focusing on clear examples, I can generate a comprehensive and accurate answer to the request.
这段代码是 Go 语言 `internal/filepathlite` 包的一部分，它实现了 `path/filepath` 包的一个子集。由于它只允许导入 "os" 包可以导入的包，因此它是一个更轻量级的版本，适用于对依赖有严格要求的场景。

以下是它实现的主要功能：

**1. 路径清理 (Clean):**

*   **功能:**  `Clean` 函数用于清理给定的路径字符串，使其成为最简洁的表示形式。它会移除多余的斜杠、将 `.` 替换为当前目录，并解析 `..` 以向上移动目录。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
)

func main() {
	path := "//a/b/../c/./d/"
	cleanedPath := filepathlite.Clean(path)
	fmt.Printf("原始路径: %s\n", path)
	fmt.Printf("清理后的路径: %s\n", cleanedPath)
}
```

*   **假设输入:** `"//a/b/../c/./d/"`
*   **预期输出:**
    ```
    原始路径: //a/b/../c/./d/
    清理后的路径: /a/c/d
    ```
*   **代码推理:** `Clean` 函数会移除开头的重复斜杠，然后处理 `b/..` 将路径向上移动一级，`.` 表示当前目录会被忽略，最终得到 `/a/c/d`。

**2. 判断是否为本地路径 (IsLocal):**

*   **功能:** `IsLocal` 函数判断给定的路径是否可以被认为是“本地”路径。在 Unix 系统上，它会检查路径是否是绝对路径或为空，以及是否包含会跳出当前目录的 `..`。在 Windows 上，其实现可能有所不同（但此处代码只展示了 Unix 的部分逻辑）。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
)

func main() {
	path1 := "relative/path"
	path2 := "/absolute/path"
	path3 := "../up/and/away"

	fmt.Printf("路径 '%s' 是否为本地路径: %t\n", path1, filepathlite.IsLocal(path1))
	fmt.Printf("路径 '%s' 是否为本地路径: %t\n", path2, filepathlite.IsLocal(path2))
	fmt.Printf("路径 '%s' 是否为本地路径: %t\n", path3, filepathlite.IsLocal(path3))
}
```

*   **假设输入:** `"relative/path"`, `"/absolute/path"`, `"../up/and/away"`
*   **预期输出:**
    ```
    路径 'relative/path' 是否为本地路径: true
    路径 '/absolute/path' 是否为本地路径: false
    路径 '../up/and/away' 是否为本地路径: false
    ```
*   **代码推理:** `relative/path` 是相对路径且不包含危险的 `..`，所以被认为是本地路径。 `/absolute/path` 是绝对路径，所以不是本地路径。 `../up/and/away` 包含了 `..`，表示可能跳出当前目录，因此也不是本地路径。

**3. 本地化路径 (Localize):**

*   **功能:** `Localize` 函数尝试将给定的路径转换为更本地化的形式。它首先使用 `fs.ValidPath` 检查路径是否有效。 具体实现 `localize(path)` 的细节在此代码片段中没有提供，但通常可能涉及处理路径中的特殊字符或根据操作系统调整路径格式。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
)

func main() {
	path := "/some/invalid*path" // 假设 * 在路径中无效
	localizedPath, err := filepathlite.Localize(path)
	if err != nil {
		fmt.Printf("本地化路径 '%s' 失败: %v\n", path, err)
	} else {
		fmt.Printf("本地化后的路径: %s\n", localizedPath)
	}
}
```

*   **假设输入:** `"/some/invalid*path"` (假设 `*` 在路径中无效)
*   **预期输出:**
    ```
    本地化路径 '/some/invalid*path' 失败: invalid path
    ```
*   **代码推理:** 由于路径包含 `*`，`fs.ValidPath` 可能会返回错误，导致 `Localize` 返回 `errInvalidPath`。

**4. 转换为斜杠分隔符 (ToSlash):**

*   **功能:** `ToSlash` 函数将路径字符串中的分隔符转换为斜杠 (`/`)。这在需要跨平台统一路径表示时很有用。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
	"runtime"
)

func main() {
	var path string
	if runtime.GOOS == "windows" {
		path = "C:\\Users\\Public\\Documents"
	} else {
		path = "/home/user/documents"
	}
	slashPath := filepathlite.ToSlash(path)
	fmt.Printf("原始路径: %s\n", path)
	fmt.Printf("斜杠路径: %s\n", slashPath)
}
```

*   **假设输入 (Windows):** `"C:\\Users\\Public\\Documents"`
*   **预期输出 (Windows):**
    ```
    原始路径: C:\Users\Public\Documents
    斜杠路径: C:/Users/Public/Documents
    ```
*   **代码推理:** 在 Windows 上，`ToSlash` 会将反斜杠 `\` 替换为斜杠 `/`。在其他系统上，如果分隔符已经是斜杠，则返回原始路径。

**5. 从斜杠分隔符转换 (FromSlash):**

*   **功能:** `FromSlash` 函数将路径字符串中的斜杠 (`/`) 转换为当前操作系统使用的分隔符。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
	"runtime"
)

func main() {
	path := "C:/Users/Public/Documents"
	osPath := filepathlite.FromSlash(path)
	fmt.Printf("斜杠路径: %s\n", path)
	fmt.Printf("操作系统路径: %s\n", osPath)
}
```

*   **假设输入 (Windows):** `"C:/Users/Public/Documents"`
*   **预期输出 (Windows):**
    ```
    斜杠路径: C:/Users/Public/Documents
    操作系统路径: C:\Users\Public\Documents
    ```
*   **代码推理:** 在 Windows 上，`FromSlash` 会将斜杠 `/` 替换为反斜杠 `\`。在其他系统上，如果分隔符已经是斜杠，则返回原始路径。

**6. 分割路径 (Split):**

*   **功能:** `Split` 函数将路径字符串分割成目录和文件名两部分。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
)

func main() {
	path := "/a/b/c/file.txt"
	dir, file := filepathlite.Split(path)
	fmt.Printf("路径: %s\n", path)
	fmt.Printf("目录: %s\n", dir)
	fmt.Printf("文件: %s\n", file)
}
```

*   **假设输入:** `"/a/b/c/file.txt"`
*   **预期输出:**
    ```
    路径: /a/b/c/file.txt
    目录: /a/b/c/
    文件: file.txt
    ```
*   **代码推理:** `Split` 函数在最后一个分隔符处分割路径。

**7. 获取文件扩展名 (Ext):**

*   **功能:** `Ext` 函数返回路径中文件的扩展名，包括点号 (`.`)。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
)

func main() {
	path := "/a/b/c/file.tar.gz"
	ext := filepathlite.Ext(path)
	fmt.Printf("路径: %s\n", path)
	fmt.Printf("扩展名: %s\n", ext)
}
```

*   **假设输入:** `"/a/b/c/file.tar.gz"`
*   **预期输出:**
    ```
    路径: /a/b/c/file.tar.gz
    扩展名: .gz
    ```
*   **代码推理:** `Ext` 从路径的末尾开始查找最后一个点号，并返回点号之后的部分。

**8. 获取文件名 (Base):**

*   **功能:** `Base` 函数返回路径的最后一个元素，通常是文件名。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
)

func main() {
	path := "/a/b/c/file.txt"
	base := filepathlite.Base(path)
	fmt.Printf("路径: %s\n", path)
	fmt.Printf("文件名: %s\n", base)
}
```

*   **假设输入:** `"/a/b/c/file.txt"`
*   **预期输出:**
    ```
    路径: /a/b/c/file.txt
    文件名: file.txt
    ```
*   **代码推理:** `Base` 返回最后一个分隔符之后的部分。

**9. 获取目录名 (Dir):**

*   **功能:** `Dir` 函数返回路径的目录部分，不包括最后一个元素（文件名）。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
)

func main() {
	path := "/a/b/c/file.txt"
	dir := filepathlite.Dir(path)
	fmt.Printf("路径: %s\n", path)
	fmt.Printf("目录: %s\n", dir)
}
```

*   **假设输入:** `"/a/b/c/file.txt"`
*   **预期输出:**
    ```
    路径: /a/b/c/file.txt
    目录: /a/b/c
    ```
*   **代码推理:** `Dir` 返回最后一个分隔符之前的部分。

**10. 获取卷名 (VolumeName):**

*   **功能:** `VolumeName` 函数返回路径的卷名。在 Windows 上，这通常是驱动器号（例如 "C:"）。在其他操作系统上，它通常为空字符串。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
	"runtime"
)

func main() {
	var path string
	if runtime.GOOS == "windows" {
		path = "C:\\Users\\Public\\Documents"
	} else {
		path = "/home/user/documents"
	}
	volume := filepathlite.VolumeName(path)
	fmt.Printf("路径: %s\n", path)
	fmt.Printf("卷名: %s\n", volume)
}
```

*   **假设输入 (Windows):** `"C:\\Users\\Public\\Documents"`
*   **预期输出 (Windows):**
    ```
    路径: C:\Users\Public\Documents
    卷名: C:
    ```
*   **假设输入 (Linux/macOS):** `"/home/user/documents"`
*   **预期输出 (Linux/macOS):**
    ```
    路径: /home/user/documents
    卷名:
    ```
*   **代码推理:** `VolumeName` 会根据操作系统提取卷名。

**11. 获取卷名长度 (VolumeNameLen):**

*   **功能:** `VolumeNameLen` 函数返回路径中卷名的长度。在 Windows 上，这通常是 2（例如 "C:" 的长度）。在其他操作系统上，它返回 0。
*   **Go 代码示例:**

```go
package main

import (
	"fmt"
	"internal/filepathlite"
	"runtime"
)

func main() {
	var path string
	if runtime.GOOS == "windows" {
		path = "C:\\Users\\Public\\Documents"
	} else {
		path = "/home/user/documents"
	}
	length := filepathlite.VolumeNameLen(path)
	fmt.Printf("路径: %s\n", path)
	fmt.Printf("卷名长度: %d\n", length)
}
```

*   **假设输入 (Windows):** `"C:\\Users\\Public\\Documents"`
*   **预期输出 (Windows):**
    ```
    路径: C:\Users\Public\Documents
    卷名长度: 2
    ```
*   **假设输入 (Linux/macOS):** `"/home/user/documents"`
*   **预期输出 (Linux/macOS):**
    ```
    路径: /home/user/documents
    卷名长度: 0
    ```
*   **代码推理:** `VolumeNameLen` 返回卷名字符串的长度。

**推理出的 Go 语言功能实现:**

从代码和注释来看，这个 `filepathlite` 包是为了提供 `path/filepath` 包的核心功能，但限制了其依赖，使其只能使用 `os` 包及其依赖项可以导入的包。这在某些受限环境或需要最小化依赖关系的场景下非常有用。

**使用者易犯错的点:**

1. **混淆斜杠方向:**  在 Windows 上，路径分隔符是反斜杠 `\`，而在其他系统上是斜杠 `/`。直接硬编码路径字符串可能会导致跨平台问题。应该使用 `filepathlite.ToSlash` 和 `filepathlite.FromSlash` 来进行转换。

    ```go
    // 错误示例 (在 Windows 上可能不起作用)
    path := "C:/Users/Public/Documents/file.txt"
    // 正确示例
    path := filepathlite.FromSlash("C:/Users/Public/Documents/file.txt")
    ```

2. **不理解 `Clean` 的作用:** 可能会认为 `Clean` 只是简单地移除多余的斜杠，而忽略了它还会处理 `.` 和 `..`。

    ```go
    path := "/a/b/../c"
    // 可能会错误地认为结果是 "/a/b/c"
    cleanedPath := filepathlite.Clean(path) // 实际结果是 "/a/c"
    ```

3. **依赖 `Localize` 进行路径规范化:**  `Localize` 的具体实现可能依赖于操作系统，因此其行为可能不完全一致。如果需要进行标准的路径清理，应该使用 `Clean`。

**总结:**

`internal/filepathlite/path.go` 提供了一组用于处理文件路径的基本操作，是标准库 `path/filepath` 的一个轻量级替代方案，特别适用于对依赖有限制的场景。了解其提供的功能和潜在的陷阱可以帮助开发者更有效地使用它。

### 提示词
```
这是路径为go/src/internal/filepathlite/path.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package filepathlite implements a subset of path/filepath,
// only using packages which may be imported by "os".
//
// Tests for these functions are in path/filepath.
package filepathlite

import (
	"errors"
	"internal/stringslite"
	"io/fs"
	"slices"
)

var errInvalidPath = errors.New("invalid path")

// A lazybuf is a lazily constructed path buffer.
// It supports append, reading previously appended bytes,
// and retrieving the final string. It does not allocate a buffer
// to hold the output until that output diverges from s.
type lazybuf struct {
	path       string
	buf        []byte
	w          int
	volAndPath string
	volLen     int
}

func (b *lazybuf) index(i int) byte {
	if b.buf != nil {
		return b.buf[i]
	}
	return b.path[i]
}

func (b *lazybuf) append(c byte) {
	if b.buf == nil {
		if b.w < len(b.path) && b.path[b.w] == c {
			b.w++
			return
		}
		b.buf = make([]byte, len(b.path))
		copy(b.buf, b.path[:b.w])
	}
	b.buf[b.w] = c
	b.w++
}

func (b *lazybuf) prepend(prefix ...byte) {
	b.buf = slices.Insert(b.buf, 0, prefix...)
	b.w += len(prefix)
}

func (b *lazybuf) string() string {
	if b.buf == nil {
		return b.volAndPath[:b.volLen+b.w]
	}
	return b.volAndPath[:b.volLen] + string(b.buf[:b.w])
}

// Clean is filepath.Clean.
func Clean(path string) string {
	originalPath := path
	volLen := volumeNameLen(path)
	path = path[volLen:]
	if path == "" {
		if volLen > 1 && IsPathSeparator(originalPath[0]) && IsPathSeparator(originalPath[1]) {
			// should be UNC
			return FromSlash(originalPath)
		}
		return originalPath + "."
	}
	rooted := IsPathSeparator(path[0])

	// Invariants:
	//	reading from path; r is index of next byte to process.
	//	writing to buf; w is index of next byte to write.
	//	dotdot is index in buf where .. must stop, either because
	//		it is the leading slash or it is a leading ../../.. prefix.
	n := len(path)
	out := lazybuf{path: path, volAndPath: originalPath, volLen: volLen}
	r, dotdot := 0, 0
	if rooted {
		out.append(Separator)
		r, dotdot = 1, 1
	}

	for r < n {
		switch {
		case IsPathSeparator(path[r]):
			// empty path element
			r++
		case path[r] == '.' && (r+1 == n || IsPathSeparator(path[r+1])):
			// . element
			r++
		case path[r] == '.' && path[r+1] == '.' && (r+2 == n || IsPathSeparator(path[r+2])):
			// .. element: remove to last separator
			r += 2
			switch {
			case out.w > dotdot:
				// can backtrack
				out.w--
				for out.w > dotdot && !IsPathSeparator(out.index(out.w)) {
					out.w--
				}
			case !rooted:
				// cannot backtrack, but not rooted, so append .. element.
				if out.w > 0 {
					out.append(Separator)
				}
				out.append('.')
				out.append('.')
				dotdot = out.w
			}
		default:
			// real path element.
			// add slash if needed
			if rooted && out.w != 1 || !rooted && out.w != 0 {
				out.append(Separator)
			}
			// copy element
			for ; r < n && !IsPathSeparator(path[r]); r++ {
				out.append(path[r])
			}
		}
	}

	// Turn empty string into "."
	if out.w == 0 {
		out.append('.')
	}

	postClean(&out) // avoid creating absolute paths on Windows
	return FromSlash(out.string())
}

// IsLocal is filepath.IsLocal.
func IsLocal(path string) bool {
	return isLocal(path)
}

func unixIsLocal(path string) bool {
	if IsAbs(path) || path == "" {
		return false
	}
	hasDots := false
	for p := path; p != ""; {
		var part string
		part, p, _ = stringslite.Cut(p, "/")
		if part == "." || part == ".." {
			hasDots = true
			break
		}
	}
	if hasDots {
		path = Clean(path)
	}
	if path == ".." || stringslite.HasPrefix(path, "../") {
		return false
	}
	return true
}

// Localize is filepath.Localize.
func Localize(path string) (string, error) {
	if !fs.ValidPath(path) {
		return "", errInvalidPath
	}
	return localize(path)
}

// ToSlash is filepath.ToSlash.
func ToSlash(path string) string {
	if Separator == '/' {
		return path
	}
	return replaceStringByte(path, Separator, '/')
}

// FromSlash is filepath.ToSlash.
func FromSlash(path string) string {
	if Separator == '/' {
		return path
	}
	return replaceStringByte(path, '/', Separator)
}

func replaceStringByte(s string, old, new byte) string {
	if stringslite.IndexByte(s, old) == -1 {
		return s
	}
	n := []byte(s)
	for i := range n {
		if n[i] == old {
			n[i] = new
		}
	}
	return string(n)
}

// Split is filepath.Split.
func Split(path string) (dir, file string) {
	vol := VolumeName(path)
	i := len(path) - 1
	for i >= len(vol) && !IsPathSeparator(path[i]) {
		i--
	}
	return path[:i+1], path[i+1:]
}

// Ext is filepath.Ext.
func Ext(path string) string {
	for i := len(path) - 1; i >= 0 && !IsPathSeparator(path[i]); i-- {
		if path[i] == '.' {
			return path[i:]
		}
	}
	return ""
}

// Base is filepath.Base.
func Base(path string) string {
	if path == "" {
		return "."
	}
	// Strip trailing slashes.
	for len(path) > 0 && IsPathSeparator(path[len(path)-1]) {
		path = path[0 : len(path)-1]
	}
	// Throw away volume name
	path = path[len(VolumeName(path)):]
	// Find the last element
	i := len(path) - 1
	for i >= 0 && !IsPathSeparator(path[i]) {
		i--
	}
	if i >= 0 {
		path = path[i+1:]
	}
	// If empty now, it had only slashes.
	if path == "" {
		return string(Separator)
	}
	return path
}

// Dir is filepath.Dir.
func Dir(path string) string {
	vol := VolumeName(path)
	i := len(path) - 1
	for i >= len(vol) && !IsPathSeparator(path[i]) {
		i--
	}
	dir := Clean(path[len(vol) : i+1])
	if dir == "." && len(vol) > 2 {
		// must be UNC
		return vol
	}
	return vol + dir
}

// VolumeName is filepath.VolumeName.
func VolumeName(path string) string {
	return FromSlash(path[:volumeNameLen(path)])
}

// VolumeNameLen returns the length of the leading volume name on Windows.
// It returns 0 elsewhere.
func VolumeNameLen(path string) int {
	return volumeNameLen(path)
}
```