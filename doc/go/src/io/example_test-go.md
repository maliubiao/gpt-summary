Response:
Let's break down the thought process to analyze the provided Go code and generate the Chinese response.

1. **Understanding the Goal:** The request asks for a description of the functionality of a Go file (`example_test.go`) demonstrating features of the `io` package. It also asks for examples, code reasoning, command-line arguments (though none are present), and common pitfalls. The response needs to be in Chinese.

2. **Initial Scan and Structure Recognition:**  The first step is to quickly scan the code and identify the structure. Notice the `package io_test` and the `import` statements. The functions all follow the `ExampleXxx` naming convention, which is standard for Go example tests. This tells us that each function is demonstrating the use of a specific `io` package function or type.

3. **Analyzing Individual `Example` Functions:**  The core of the analysis lies in processing each `Example` function one by one. For each function, the process is as follows:

    * **Identify the Core `io` Function/Type:** Look at the function call within the `Example` function. For instance, `io.Copy`, `io.CopyBuffer`, `io.CopyN`, `io.ReadAtLeast`, etc. This immediately tells you what's being demonstrated.

    * **Understand the Purpose of the `io` Function/Type:**  Recall or look up the documentation for the identified `io` function. What does it do? What are its parameters? What does it return?

    * **Analyze the Example Code:**  Examine how the `io` function is being used in the example. What inputs are being provided? What's the expected output based on the `// Output:` comment?

    * **Formulate a Functionality Description:**  Summarize the purpose of the `Example` function in clear, concise Chinese. Focus on what the demonstrated `io` function does.

    * **Create a Code Example (if needed):** The provided code *is* the example. So, in this case, we don't need to create *new* examples. However, for the "reasoning" part, we might select portions of the existing example to illustrate a specific point.

    * **Infer Inputs and Outputs (for Reasoning):**  The `// Output:` comments provide the direct output. The input is derived from the `strings.NewReader` calls or the data being written.

    * **Look for Command-Line Arguments:** Scan the code for `os.Args` or any usage of the `flag` package. In this case, there are none.

    * **Identify Potential Pitfalls:** Based on the behavior of the `io` function, think about common mistakes users might make. For example, with `io.CopyBuffer`, using a buffer that's too small. With `io.ReadAtLeast` and `io.ReadFull`, the buffer size relative to the data source is crucial.

4. **Synthesizing the Information:**  After analyzing each `Example` function, organize the information into a coherent response. Use clear headings and bullet points for readability.

5. **Translating to Chinese:**  Translate all the generated descriptions, explanations, and code comments into natural-sounding Chinese. Pay attention to technical terms and ensure accurate translation.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe I should explain the `import` statements in detail.
* **Correction:** The request is about the *functionality* of the file, focusing on the `io` package usage. The imports are supporting infrastructure. Briefly mentioning them is sufficient.

* **Initial thought:** For reasoning, I should rewrite the entire example code.
* **Correction:** The provided examples are already good. It's more efficient and clearer to reference parts of the existing code and highlight specific inputs and outputs.

* **Initial thought:**  I need to come up with completely novel pitfalls.
* **Correction:** The examples themselves often illustrate potential pitfalls (e.g., the `shortBuf` example in `ExampleReadAtLeast`). Focus on the errors shown in the output.

* **Double-checking the Chinese:** After drafting the Chinese response, reread it to ensure clarity, accuracy, and natural flow. Are there any awkward phrasings?  Are the technical terms translated correctly?

By following this structured approach, analyzing each example systematically, and focusing on the core request, we can generate a comprehensive and accurate response like the example you provided. The key is to break down the problem into smaller, manageable chunks and then synthesize the results.
这是路径为 `go/src/io/example_test.go` 的 Go 语言实现的一部分，它主要用于展示 Go 标准库 `io` 包中各种函数和类型的用法。 这些示例函数都遵循 `ExampleXxx` 的命名约定，这在 Go 语言中表示这是一个可执行的示例代码，可以作为文档的一部分展示，并且可以通过 `go test` 命令运行。

以下是各个示例函数的功能以及它们展示的 `io` 包的特性：

**1. `ExampleCopy()`**

* **功能:** 将一个 `io.Reader` 中的所有数据复制到 `io.Writer` 中。
* **展示的 `io` 功能:** `io.Copy(dst Writer, src Reader) (written int64, err error)`
* **代码推理:**
    * **假设输入:**  `r` 是一个包含字符串 "some io.Reader stream to be read\n" 的 `strings.Reader`。
    * **处理:** `io.Copy` 将 `r` 中的内容读取出来，并写入到 `os.Stdout` (标准输出)。
    * **预期输出:**  标准输出会打印出 "some io.Reader stream to be read\n"。

**2. `ExampleCopyBuffer()`**

* **功能:** 类似于 `io.Copy`，但允许用户提供一个缓冲区，以提高复制效率，并避免在每次复制时都分配新的内存。
* **展示的 `io` 功能:** `io.CopyBuffer(dst Writer, src Reader, buf []byte) (written int64, err error)`
* **代码推理:**
    * **假设输入:** `r1` 和 `r2` 分别是包含字符串 "first reader\n" 和 "second reader\n" 的 `strings.Reader`。 `buf` 是一个长度为 8 的字节切片。
    * **处理:**  `io.CopyBuffer` 使用提供的 `buf` 作为临时缓冲区，将 `r1` 和 `r2` 的内容依次复制到 `os.Stdout`。  注意，`buf` 在两次复制中被复用。
    * **预期输出:** 标准输出会先打印 "first reader\n"，然后打印 "second reader\n"。

**3. `ExampleCopyN()`**

* **功能:** 从 `io.Reader` 中复制指定数量的字节到 `io.Writer`。
* **展示的 `io` 功能:** `io.CopyN(dst Writer, src Reader, n int64) (written int64, err error)`
* **代码推理:**
    * **假设输入:** `r` 是一个包含字符串 "some io.Reader stream to be read" 的 `strings.Reader`。
    * **处理:** `io.CopyN` 从 `r` 中读取前 4 个字节（"some"），并写入到 `os.Stdout`。
    * **预期输出:** 标准输出会打印 "some"。

**4. `ExampleReadAtLeast()`**

* **功能:**  尝试从 `io.Reader` 中读取至少指定数量的字节到给定的缓冲区。
* **展示的 `io` 功能:** `io.ReadAtLeast(r Reader, buf []byte, min int) (n int, err error)`
* **代码推理:**
    * **第一次调用:**
        * **假设输入:** `r` 包含 "some io.Reader stream to be read\n"，`buf` 长度为 14，`min` 为 4。
        * **处理:** `io.ReadAtLeast` 尝试读取至少 4 个字节。由于缓冲区足够大，它可以读取到 "some io.Reader" 并填充到 `buf` 中。
        * **预期输出:**  打印 "some io.Reader"。
    * **第二次调用:**
        * **假设输入:** `r` 剩余的内容，`shortBuf` 长度为 3， `min` 为 4。
        * **处理:** `io.ReadAtLeast` 尝试读取至少 4 个字节，但 `shortBuf` 只能容纳 3 个字节，因此返回一个错误，提示缓冲区太短。
        * **预期输出:** 打印 "error: short buffer"。
    * **第三次调用:**
        * **假设输入:** `r` 剩余的内容，`longBuf` 长度为 64，`min` 为 64。
        * **处理:** `io.ReadAtLeast` 尝试读取至少 64 个字节，但 `r` 中剩余的内容不足 64 字节，因此返回 `io.ErrUnexpectedEOF` 错误。
        * **预期输出:** 打印 "error: unexpected EOF"。

**5. `ExampleReadFull()`**

* **功能:** 尝试从 `io.Reader` 中读取**完整**的缓冲区。如果读取的字节数少于缓冲区的大小，则返回错误。
* **展示的 `io` 功能:** `io.ReadFull(r Reader, buf []byte) (n int, err error)`
* **代码推理:**
    * **第一次调用:**
        * **假设输入:** `r` 包含 "some io.Reader stream to be read\n"，`buf` 长度为 4。
        * **处理:** `io.ReadFull` 读取 `r` 的前 4 个字节 ("some") 并填充到 `buf`。
        * **预期输出:** 打印 "some"。
    * **第二次调用:**
        * **假设输入:** `r` 剩余的内容，`longBuf` 长度为 64。
        * **处理:** `io.ReadFull` 尝试读取 64 个字节，但 `r` 中剩余的内容不足 64 字节，因此返回 `io.ErrUnexpectedEOF` 错误。
        * **预期输出:** 打印 "error: unexpected EOF"。

**6. `ExampleWriteString()`**

* **功能:** 将字符串写入 `io.Writer`。
* **展示的 `io` 功能:** `io.WriteString(w Writer, s string) (n int, err error)`
* **代码推理:**
    * **假设输入:** 字符串 "Hello World"。
    * **处理:** `io.WriteString` 将 "Hello World" 写入到 `os.Stdout`。
    * **预期输出:** 标准输出会打印 "Hello World"。

**7. `ExampleLimitReader()`**

* **功能:** 创建一个 `io.Reader`，它只从底层的 `io.Reader` 中读取有限数量的字节。
* **展示的 `io` 功能:** `io.LimitReader(r Reader, n int64) Reader`
* **代码推理:**
    * **假设输入:** `r` 包含 "some io.Reader stream to be read\n"，限制读取 4 个字节。
    * **处理:** `io.LimitReader` 创建了一个新的 `io.Reader`，该读取器最多只能读取 `r` 的前 4 个字节。 `io.Copy` 将这个受限的读取器内容复制到 `os.Stdout`。
    * **预期输出:** 标准输出会打印 "some"。

**8. `ExampleMultiReader()`**

* **功能:** 创建一个 `io.Reader`，它将多个 `io.Reader` 串联起来，就像它们是一个单一的流一样。
* **展示的 `io` 功能:** `io.MultiReader(readers ...Reader) Reader`
* **代码推理:**
    * **假设输入:** `r1` 包含 "first reader "，`r2` 包含 "second reader "，`r3` 包含 "third reader\n"。
    * **处理:** `io.MultiReader` 创建了一个新的 `io.Reader`，它首先读取 `r1` 的内容，然后读取 `r2` 的内容，最后读取 `r3` 的内容。 `io.Copy` 将这个组合的读取器内容复制到 `os.Stdout`。
    * **预期输出:** 标准输出会打印 "first reader second reader third reader\n"。

**9. `ExampleTeeReader()`**

* **功能:** 创建一个 `io.Reader`，它在读取数据的同时，也将数据写入到另一个 `io.Writer`。就像一个分流器。
* **展示的 `io` 功能:** `io.TeeReader(r Reader, w Writer) Reader`
* **代码推理:**
    * **假设输入:** `r` 包含 "some io.Reader stream to be read\n"。
    * **处理:** `io.TeeReader` 创建了一个新的 `io.Reader`。 当从这个新的读取器读取数据时，数据会同时写入到 `os.Stdout`。 `io.ReadAll` 从 `TeeReader` 中读取所有数据。
    * **预期输出:** 标准输出会打印 "some io.Reader stream to be read\n"。

**10. `ExampleSectionReader()`**

* **功能:** 创建一个 `io.Reader`，它代表另一个 `io.Reader` 的一个特定部分（从偏移量开始，读取指定长度）。
* **展示的 `io` 功能:** `io.NewSectionReader(r ReaderAt, off int64, n int64) *SectionReader`
* **代码推理:**
    * **假设输入:** `r` 包含 "some io.Reader stream to be read\n"，从偏移量 5 开始，读取 17 个字节。
    * **处理:** `io.NewSectionReader` 创建了一个新的 `io.Reader`，它只读取 `r` 中从第 6 个字符（索引为 5）开始的 17 个字节，即 "io.Reader stream"。 `io.Copy` 将这个部分内容复制到 `os.Stdout`。
    * **预期输出:** 标准输出会打印 "io.Reader stream"。

**11. `ExampleSectionReader_Read()`**

* **功能:**  演示 `SectionReader` 的 `Read` 方法，该方法从其定义的节区中读取数据。
* **展示的 `io` 功能:** `(*SectionReader) Read(p []byte) (n int, err error)`
* **代码推理:**
    * **假设输入:** `SectionReader` 被创建为读取 "some io.Reader stream to be read\n" 的第 6 到 22 个字节，`buf` 长度为 9。
    * **处理:** `s.Read(buf)` 从 `SectionReader` 定义的节区中读取最多 9 个字节到 `buf` 中。
    * **预期输出:** 打印 "io.Reader"。

**12. `ExampleSectionReader_ReadAt()`**

* **功能:** 演示 `SectionReader` 的 `ReadAt` 方法，该方法从其定义的节区的指定偏移量处开始读取数据到缓冲区。
* **展示的 `io` 功能:** `(*SectionReader) ReadAt(p []byte, off int64) (n int, err error)`
* **代码推理:**
    * **假设输入:** `SectionReader` 被创建为读取 "some io.Reader stream to be read\n" 的第 6 到 22 个字节，尝试从节区的偏移量 10 处读取 6 个字节到 `buf`。
    * **处理:** `s.ReadAt(buf, 10)` 从 `SectionReader` 代表的 "io.Reader stream" 的第 11 个字符（索引为 10）开始读取 6 个字节到 `buf` 中。 "io.Reader stream" 的第 11 个字符是 's'，接下来的 5 个字符是 "tream"。
    * **预期输出:** 打印 "stream"。

**13. `ExampleSectionReader_Seek()`**

* **功能:** 演示 `SectionReader` 的 `Seek` 方法，该方法用于设置后续 `Read` 操作的起始位置，相对于节区的开头。
* **展示的 `io` 功能:** `(*SectionReader) Seek(offset int64, whence int) (ret int64, err error)`
* **代码推理:**
    * **假设输入:** `SectionReader` 被创建为读取 "some io.Reader stream to be read\n" 的第 6 到 22 个字节，尝试将读取位置移动到节区的第 11 个字节（索引为 10）。
    * **处理:** `s.Seek(10, io.SeekStart)` 将 `SectionReader` 的读取位置设置为其节区的第 11 个字节。然后 `io.Copy` 从这个位置开始读取剩余的内容。
    * **预期输出:** 标准输出会打印 "stream"。

**14. `ExampleSectionReader_Size()`**

* **功能:** 演示 `SectionReader` 的 `Size` 方法，该方法返回其代表的节区的总大小。
* **展示的 `io` 功能:** `(*SectionReader) Size() int64`
* **代码推理:**
    * **假设输入:** `SectionReader` 被创建为读取 "some io.Reader stream to be read\n" 的第 6 到 22 个字节，长度为 17。
    * **处理:** `s.Size()` 返回 `SectionReader` 所代表的节区的长度。
    * **预期输出:** 打印 "17"。

**15. `ExampleSeeker_Seek()`**

* **功能:** 演示实现了 `io.Seeker` 接口的类型的 `Seek` 方法，该方法用于改变读取或写入的偏移量。
* **展示的 `io` 功能:** `(r *Reader) Seek(offset int64, whence int) (int64, error)` (这里以 `strings.Reader` 为例)
* **代码推理:**
    * **第一次调用:**
        * **假设输入:** `r` 是一个包含 "some io.Reader stream to be read\n" 的 `strings.Reader`。
        * **处理:** `r.Seek(5, io.SeekStart)` 将读取位置移动到字符串的第 6 个字符（索引为 5）。然后 `io.Copy` 从这个位置开始读取并输出。
        * **预期输出:** 标准输出会打印 "io.Reader stream to be read\n"。
    * **第二次调用:**
        * **假设输入:**  `r` 仍然是同一个 `strings.Reader`。
        * **处理:** `r.Seek(-5, io.SeekEnd)` 将读取位置移动到字符串末尾倒数第 5 个字符的位置。然后 `io.Copy` 从这个位置开始读取并输出。
        * **预期输出:** 标准输出会打印 "read\n"。

**16. `ExampleMultiWriter()`**

* **功能:** 创建一个 `io.Writer`，写入它的数据会同时写入到多个底层的 `io.Writer`。
* **展示的 `io` 功能:** `io.MultiWriter(writers ...Writer) Writer`
* **代码推理:**
    * **假设输入:** `r` 包含 "some io.Reader stream to be read\n"。 `buf1` 和 `buf2` 是 `strings.Builder` 类型的变量。
    * **处理:** `io.MultiWriter` 创建了一个新的 `io.Writer`，当数据写入到这个新的写入器时，数据会同时写入到 `buf1` 和 `buf2`。 `io.Copy` 将 `r` 的内容写入到这个 `MultiWriter`。
    * **预期输出:**  会打印两次 "some io.Reader stream to be read\n"，一次来自 `buf1`，一次来自 `buf2`。

**17. `ExamplePipe()`**

* **功能:** 创建一个同步的内存管道。它返回一个可以读取的 `io.Reader` 和一个可以写入的 `io.Writer`，写入到 `Writer` 的数据可以从 `Reader` 中读取出来。
* **展示的 `io` 功能:** `io.Pipe() (*PipeReader, *PipeWriter)`
* **代码推理:**
    * **处理:**  `io.Pipe()` 创建了一个读取器 `r` 和一个写入器 `w`。 在一个 Goroutine 中，将字符串 "some io.Reader stream to be read\n" 写入到 `w`，然后关闭 `w`。 主 Goroutine 使用 `io.Copy` 从 `r` 中读取数据并写入到 `os.Stdout`。
    * **预期输出:** 标准输出会打印 "some io.Reader stream to be read\n"。

**18. `ExampleReadAll()`**

* **功能:** 从 `io.Reader` 中读取所有剩余的数据，直到遇到 EOF 或发生错误。
* **展示的 `io` 功能:** `io.ReadAll(r Reader) ([]byte, error)`
* **代码推理:**
    * **假设输入:** `r` 包含 "Go is a general-purpose language designed with systems programming in mind."。
    * **处理:** `io.ReadAll` 从 `r` 中读取所有数据到一个字节切片 `b` 中。
    * **预期输出:** 打印 "Go is a general-purpose language designed with systems programming in mind."。

**总结功能:**

总的来说，这个 `example_test.go` 文件通过多个示例展示了 `io` 包中用于处理输入和输出流的各种核心功能，包括：

* **数据复制:** `Copy`, `CopyBuffer`, `CopyN`
* **数据读取:** `ReadAtLeast`, `ReadFull`, `ReadAll`
* **数据写入:** `WriteString`
* **流的限制和组合:** `LimitReader`, `MultiReader`, `TeeReader`
* **流的截取和定位:** `SectionReader`, `Seeker`
* **多路写入:** `MultiWriter`
* **内存管道:** `Pipe`

**命令行参数:**

这个代码示例本身不涉及任何命令行参数的处理。它是一个测试文件，主要通过 `go test` 命令运行，并不会接收用户提供的命令行参数。

**使用者易犯错的点:**

* **`io.CopyBuffer` 中缓冲区大小的选择:** 如果提供的缓冲区太小，可能会导致多次小的读取和写入操作，降低效率。最佳缓冲区大小通常与操作系统或硬件的块大小有关。
* **`io.ReadAtLeast` 和 `io.ReadFull` 中缓冲区大小与预期读取量的不匹配:**
    * 如果提供的缓冲区小于 `min` (对于 `ReadAtLeast`) 或预期的全部数据 (对于 `ReadFull`)，会导致错误。
    * 如果 `io.Reader` 中的数据量少于 `min` 或缓冲区大小，也会导致 `io.ErrUnexpectedEOF` 错误。
    * **示例 (针对 `ReadAtLeast`):**

    ```go
    package main

    import (
        "fmt"
        "io"
        "strings"
    )

    func main() {
        r := strings.NewReader("abc")
        buf := make([]byte, 5)
        n, err := io.ReadAtLeast(r, buf, 4)
        if err != nil {
            fmt.Println("Error:", err) // 输出: Error: unexpected EOF
        } else {
            fmt.Printf("Read %d bytes: %s\n", n, buf[:n])
        }
    }
    ```

* **不正确地使用 `Seek` 方法的 `whence` 参数:**  `io.SeekStart`, `io.SeekCurrent`, `io.SeekEnd` 的含义需要理解清楚，否则可能导致定位到错误的位置。
* **忘记关闭管道的写入端:** 在使用 `io.Pipe` 时，如果写入端没有正确关闭，读取端可能会一直阻塞等待数据。

总而言之，这个文件是一个很好的学习 `io` 包用法的资源，通过这些具体的例子，开发者可以更好地理解和使用 Go 语言中处理输入输出的核心工具。

Prompt: 
```
这是路径为go/src/io/example_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package io_test

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func ExampleCopy() {
	r := strings.NewReader("some io.Reader stream to be read\n")

	if _, err := io.Copy(os.Stdout, r); err != nil {
		log.Fatal(err)
	}

	// Output:
	// some io.Reader stream to be read
}

func ExampleCopyBuffer() {
	r1 := strings.NewReader("first reader\n")
	r2 := strings.NewReader("second reader\n")
	buf := make([]byte, 8)

	// buf is used here...
	if _, err := io.CopyBuffer(os.Stdout, r1, buf); err != nil {
		log.Fatal(err)
	}

	// ... reused here also. No need to allocate an extra buffer.
	if _, err := io.CopyBuffer(os.Stdout, r2, buf); err != nil {
		log.Fatal(err)
	}

	// Output:
	// first reader
	// second reader
}

func ExampleCopyN() {
	r := strings.NewReader("some io.Reader stream to be read")

	if _, err := io.CopyN(os.Stdout, r, 4); err != nil {
		log.Fatal(err)
	}

	// Output:
	// some
}

func ExampleReadAtLeast() {
	r := strings.NewReader("some io.Reader stream to be read\n")

	buf := make([]byte, 14)
	if _, err := io.ReadAtLeast(r, buf, 4); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf)

	// buffer smaller than minimal read size.
	shortBuf := make([]byte, 3)
	if _, err := io.ReadAtLeast(r, shortBuf, 4); err != nil {
		fmt.Println("error:", err)
	}

	// minimal read size bigger than io.Reader stream
	longBuf := make([]byte, 64)
	if _, err := io.ReadAtLeast(r, longBuf, 64); err != nil {
		fmt.Println("error:", err)
	}

	// Output:
	// some io.Reader
	// error: short buffer
	// error: unexpected EOF
}

func ExampleReadFull() {
	r := strings.NewReader("some io.Reader stream to be read\n")

	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf)

	// minimal read size bigger than io.Reader stream
	longBuf := make([]byte, 64)
	if _, err := io.ReadFull(r, longBuf); err != nil {
		fmt.Println("error:", err)
	}

	// Output:
	// some
	// error: unexpected EOF
}

func ExampleWriteString() {
	if _, err := io.WriteString(os.Stdout, "Hello World"); err != nil {
		log.Fatal(err)
	}

	// Output: Hello World
}

func ExampleLimitReader() {
	r := strings.NewReader("some io.Reader stream to be read\n")
	lr := io.LimitReader(r, 4)

	if _, err := io.Copy(os.Stdout, lr); err != nil {
		log.Fatal(err)
	}

	// Output:
	// some
}

func ExampleMultiReader() {
	r1 := strings.NewReader("first reader ")
	r2 := strings.NewReader("second reader ")
	r3 := strings.NewReader("third reader\n")
	r := io.MultiReader(r1, r2, r3)

	if _, err := io.Copy(os.Stdout, r); err != nil {
		log.Fatal(err)
	}

	// Output:
	// first reader second reader third reader
}

func ExampleTeeReader() {
	var r io.Reader = strings.NewReader("some io.Reader stream to be read\n")

	r = io.TeeReader(r, os.Stdout)

	// Everything read from r will be copied to stdout.
	if _, err := io.ReadAll(r); err != nil {
		log.Fatal(err)
	}

	// Output:
	// some io.Reader stream to be read
}

func ExampleSectionReader() {
	r := strings.NewReader("some io.Reader stream to be read\n")
	s := io.NewSectionReader(r, 5, 17)

	if _, err := io.Copy(os.Stdout, s); err != nil {
		log.Fatal(err)
	}

	// Output:
	// io.Reader stream
}

func ExampleSectionReader_Read() {
	r := strings.NewReader("some io.Reader stream to be read\n")
	s := io.NewSectionReader(r, 5, 17)

	buf := make([]byte, 9)
	if _, err := s.Read(buf); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", buf)

	// Output:
	// io.Reader
}

func ExampleSectionReader_ReadAt() {
	r := strings.NewReader("some io.Reader stream to be read\n")
	s := io.NewSectionReader(r, 5, 17)

	buf := make([]byte, 6)
	if _, err := s.ReadAt(buf, 10); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s\n", buf)

	// Output:
	// stream
}

func ExampleSectionReader_Seek() {
	r := strings.NewReader("some io.Reader stream to be read\n")
	s := io.NewSectionReader(r, 5, 17)

	if _, err := s.Seek(10, io.SeekStart); err != nil {
		log.Fatal(err)
	}

	if _, err := io.Copy(os.Stdout, s); err != nil {
		log.Fatal(err)
	}

	// Output:
	// stream
}

func ExampleSectionReader_Size() {
	r := strings.NewReader("some io.Reader stream to be read\n")
	s := io.NewSectionReader(r, 5, 17)

	fmt.Println(s.Size())

	// Output:
	// 17
}

func ExampleSeeker_Seek() {
	r := strings.NewReader("some io.Reader stream to be read\n")

	r.Seek(5, io.SeekStart) // move to the 5th char from the start
	if _, err := io.Copy(os.Stdout, r); err != nil {
		log.Fatal(err)
	}

	r.Seek(-5, io.SeekEnd)
	if _, err := io.Copy(os.Stdout, r); err != nil {
		log.Fatal(err)
	}

	// Output:
	// io.Reader stream to be read
	// read
}

func ExampleMultiWriter() {
	r := strings.NewReader("some io.Reader stream to be read\n")

	var buf1, buf2 strings.Builder
	w := io.MultiWriter(&buf1, &buf2)

	if _, err := io.Copy(w, r); err != nil {
		log.Fatal(err)
	}

	fmt.Print(buf1.String())
	fmt.Print(buf2.String())

	// Output:
	// some io.Reader stream to be read
	// some io.Reader stream to be read
}

func ExamplePipe() {
	r, w := io.Pipe()

	go func() {
		fmt.Fprint(w, "some io.Reader stream to be read\n")
		w.Close()
	}()

	if _, err := io.Copy(os.Stdout, r); err != nil {
		log.Fatal(err)
	}

	// Output:
	// some io.Reader stream to be read
}

func ExampleReadAll() {
	r := strings.NewReader("Go is a general-purpose language designed with systems programming in mind.")

	b, err := io.ReadAll(r)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", b)

	// Output:
	// Go is a general-purpose language designed with systems programming in mind.
}

"""



```