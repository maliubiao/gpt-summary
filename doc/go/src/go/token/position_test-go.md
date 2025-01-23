Response:
Let's break down the thought process for analyzing this Go test file.

**1. Understanding the Goal:**

The primary goal is to understand what the Go code in `position_test.go` is testing. This means identifying the functionalities being exercised and how the tests are structured.

**2. Initial Scan for Keywords and Structure:**

I'd start by scanning the code for keywords that hint at the purpose and structure:

* `"testing"`:  Immediately signals that this is a test file.
* `func Test...`:  Identifies individual test functions. This is a standard Go testing convention.
* `FileSet`, `File`, `Position`, `NoPos`:  These type names suggest the core components being tested. I'd note these down as key elements.
* `checkPos`: This function appears to be a helper for comparing `Position` values. It's important for understanding how assertions are made.
* `AddFile`, `AddLine`, `SetLines`, `SetLinesForContent`, `Position`, `PositionFor`, `Offset`, `LineStart`, `RemoveFile`, `AddLineColumnInfo`: These are methods on `FileSet` and `File` that likely represent the core functionalities being tested.
* `sync.WaitGroup`: Indicates testing of concurrency and potential race conditions.

**3. Analyzing Individual Test Functions:**

I'd go through each `Test...` function and try to understand its specific purpose:

* **`TestNoPos`:** Seems to be testing the `NoPos` constant, likely representing an invalid or unset position. It checks if it's correctly identified as invalid and how it interacts with `FileSet`.
* **`TestPositions`:** This appears to be a major test, using a `tests` slice of structs. Each struct likely defines a test case with a filename, source code (or size), and line break information. The test iterates through these cases, adding files, lines, and verifying the correctness of position calculations using various methods. The use of `verifyPositions` is a strong indicator of this.
* **`TestLineInfo`:** Focuses on `AddLineInfo`, suggesting it tests the ability to override default line/column information.
* **`TestFiles`:**  Tests the `FileSet.Iterate` method, ensuring that added files can be iterated over correctly.
* **`TestFileSetPastEnd`:** Checks the behavior of `FileSet.File` when given a position beyond the range of any file.
* **`TestFileSetCacheUnlikely`:**  Seems to be testing the internal caching mechanism of `FileSet` and ensuring that retrieving files by their starting position works correctly.
* **`TestFileSetRace` and `TestFileSetRace2`:**  Explicitly test for race conditions in concurrent access to `FileSet` and `File` methods. This indicates that thread-safety is an important aspect of these types.
* **`TestPositionFor`:**  Specifically tests the `PositionFor` method, including how it handles `//line` directives to adjust file names and line numbers.
* **`TestLineStart`:** Tests the `File.LineStart` method, which should return the starting position of a given line.
* **`TestRemoveFile`:** Tests the `FileSet.RemoveFile` functionality and verifies that positions associated with removed files become invalid.
* **`TestFileAddLineColumnInfo`:** Tests the `File.AddLineColumnInfo` method for adding more detailed position information, and handles edge cases like out-of-bounds offsets.
* **`TestIssue57490`:** This is a specific regression test for a reported issue. It likely tests for panics in edge cases involving out-of-bounds positions and offsets. The comment about `debug` is crucial for understanding this test.

**3. Identifying Functionality and Examples:**

Based on the test function analysis, I would deduce the following Go language functionalities being implemented and provide examples:

* **Tracking Source Code Positions:** The core functionality is tracking the filename, offset, line number, and column number of specific locations within source code. The `Position` struct represents this.
* **Managing Multiple Files:** The `FileSet` is responsible for managing a collection of source files.
* **Mapping Offsets to Line and Column:**  The `File` type allows mapping byte offsets within a file to line and column numbers.
* **Handling `//line` Directives:** The code can interpret `//line` comments to adjust the reported filename and line number for subsequent code. This is useful for preprocessors or generated code.
* **Concurrency Safety:** The tests explicitly check for race conditions, indicating that `FileSet` and `File` are designed to be used concurrently.

**4. Inferring Code Implementation (Even Without Seeing the Implementation):**

Based on the test methods, I can infer some aspects of the underlying implementation:

* `FileSet` likely stores a sorted list or map of `File` objects, allowing efficient lookup of the file containing a given position.
* `File` likely stores the size of the file and a sorted list of line break offsets to quickly calculate line and column numbers.
* The `PositionFor` method probably involves searching for the last preceding `//line` directive to adjust the filename and line number.

**5. Identifying Potential Pitfalls:**

Based on the tests, I can identify some potential mistakes users might make:

* **Assuming Line Numbers Start at 0:**  The tests consistently use 1-based indexing for line numbers.
* **Incorrectly Calculating Offsets:**  Off-by-one errors when dealing with byte offsets are common.
* **Not Considering `//line` Directives:**  Tools that process Go code need to be aware of `//line` directives to correctly map positions in generated code back to the original source.

**6. Structuring the Answer:**

Finally, I would organize the findings into a structured answer, using clear headings and examples, as demonstrated in the provided good answer. This involves summarizing the functionality, providing code examples, explaining command-line arguments (if any were present, which they weren't in this case), and highlighting potential pitfalls. The use of code blocks and clear explanations is crucial for readability.
这是一个Go语言的测试文件，专门用于测试 `go/token` 包中与源代码位置 (`Position`) 相关的功能。 让我们逐一分析它的功能并提供代码示例。

**文件功能概览:**

该测试文件主要测试了 `token` 包中的以下核心功能：

1. **表示源代码位置 (`Position`):**  测试 `Position` 结构体是否能正确存储和比较文件名、偏移量 (Offset)、行号 (Line) 和列号 (Column)。
2. **"无位置" 的表示 (`NoPos`):** 测试 `NoPos` 常量是否正确表示一个无效的位置。
3. **文件集合 (`FileSet`):**
    * **添加文件 (`AddFile`):** 测试向 `FileSet` 添加文件，并验证文件名和大小是否正确记录。
    * **通过位置查找文件 (`File`):** 测试通过给定的 `Pos` (代表文件中的一个偏移量) 能否正确找到对应的 `File` 对象。
    * **迭代文件 (`Iterate`):** 测试能否遍历 `FileSet` 中所有已添加的文件。
    * **移除文件 (`RemoveFile`):** 测试从 `FileSet` 中移除文件的功能。
4. **文件 (`File`):**
    * **添加行信息 (`AddLine`):** 测试向 `File` 对象添加换行符的偏移量，从而记录文件的行信息。
    * **设置所有行信息 (`SetLines`, `SetLinesForContent`):** 测试一次性设置文件的所有行信息。 `SetLinesForContent` 会根据提供的源代码内容自动计算换行符。
    * **获取位置信息 (`Position`):** 测试通过 `File` 对象和偏移量获取对应的 `Position` 信息 (文件名、偏移量、行号、列号)。
    * **通过位置获取偏移量 (`Offset`):** 测试通过 `Pos` 值反向获取其在文件中的偏移量。
    * **通过偏移量获取位置 (`Pos`):** 测试通过文件内的偏移量获取对应的 `Pos` 值。
    * **根据位置获取调整后的位置信息 (`PositionFor`):** 测试在存在 `//line` 注释的情况下，如何获取调整后的文件名和行号。
    * **获取行首位置 (`LineStart`):** 测试获取指定行号的起始位置。
    * **添加更详细的行列信息 (`AddLineColumnInfo`):**  测试添加带有特定文件名、行号和列号的行信息，用于覆盖默认的行列计算。
5. **并发安全性:**  测试在并发环境下使用 `FileSet` 和 `File` 的方法 (如 `Position`, `AddLine`) 是否会引发竞态条件。

**Go 代码示例:**

以下是一些基于测试用例推断出的 `token` 包功能的示例：

```go
package main

import (
	"fmt"
	"go/token"
)

func main() {
	// 创建一个新的文件集合
	fset := token.NewFileSet()

	// 添加一个名为 "example.go" 的文件，大小为 25 字节
	file := fset.AddFile("example.go", 1, 25)

	// 设置文件的行信息 (换行符的偏移量)
	file.SetLines([]int{0, 10, 24}) // 假设换行符在偏移量 0, 10, 24 处

	// 或者，根据文件内容自动设置行信息
	content := []byte("package main\n\nimport \"fmt\"\n")
	file.SetLinesForContent(content)

	// 获取偏移量 5 的位置信息
	pos := file.Pos(5)
	position := fset.Position(pos)
	fmt.Printf("Offset 5 的位置信息: %s\n", position) // 输出: example.go:1:6

	// 获取偏移量 12 的位置信息
	pos2 := file.Pos(12)
	position2 := fset.Position(pos2)
	fmt.Printf("Offset 12 的位置信息: %s\n", position2) // 输出: example.go:3:1

	// 使用 PositionFor 处理 //line 指令
	srcWithLine := []byte(`package main

//line another.go:10
import "fmt"
`)
	fileWithLine := fset.AddFile("withline.go", 1, len(srcWithLine))
	fileWithLine.SetLinesForContent(srcWithLine)
	posLine := fileWithLine.Pos(15)
	adjustedPosition := fset.PositionFor(posLine, true)
	fmt.Printf("//line 指令后的位置信息: %s\n", adjustedPosition) // 输出: another.go:10:1

	// 获取第二行的起始位置
	lineStartPos := file.LineStart(2)
	lineStartPosition := fset.Position(lineStartPos)
	fmt.Printf("第二行的起始位置: %s\n", lineStartPosition) // 输出: example.go:2:1
}
```

**假设的输入与输出 (针对 `verifyPositions` 函数):**

`verifyPositions` 函数在测试中被多次调用，假设我们有以下输入：

* `fset`: 一个已经添加了文件的 `FileSet`。
* `f`:  一个 `File` 对象，代表名为 "test.go" 的文件，大小为 15 字节。
* `lines`: `[]int{0, 5, 10}`，表示换行符的偏移量。

**推断 `verifyPositions` 的行为:**

`verifyPositions` 会遍历文件 `f` 的每个字节偏移量 (从 0 到 14)。对于每个偏移量 `offs`：

1. **`f.Pos(offs)`:**  将偏移量转换为 `Pos` 值。
2. **`f.Offset(p)`:** 将 `Pos` 值转换回偏移量 `offs2`。 **假设输入**: `offs = 7`，则 `p` 可能为某个代表偏移量 7 的内部值， `offs2` 应该为 7。
3. **比较 `offs` 和 `offs2`:** 如果不相等，则测试失败。
4. **`linecol(lines, offs)`:**  调用 `linecol` 函数计算给定偏移量所在的行号和列号。 **假设输入**: `offs = 7`，由于 `5 <= 7 < 10`，则 `linecol` 返回 `line = 2`, `col = 7 - 5 + 1 = 3`。
5. **`f.Position(f.Pos(offs))` 和 `fset.Position(p)`:**  获取偏移量对应的 `Position` 信息。 **假设输入**: `offs = 7`，预期输出的 `Position` 为 `{Filename: "test.go", Offset: 7, Line: 2, Column: 3}`。
6. **使用 `checkPos` 比较期望和实际的 `Position`。**

**命令行参数的具体处理:**

从提供的代码片段来看，这个测试文件本身 **不涉及** 任何命令行参数的处理。它是一个纯粹的单元测试文件，通过 `go test` 命令运行。

**使用者易犯错的点:**

1. **行号和列号从 1 开始:**  `token.Position` 中的 `Line` 和 `Column` 字段是从 1 开始计数的，而不是从 0 开始。初学者可能容易混淆。

   ```go
   // 假设文件内容是 "abc\ndef"
   fset := token.NewFileSet()
   file := fset.AddFile("test.txt", 1, 7)
   file.SetLines([]int{0, 3}) // 换行符在偏移量 3

   pos := file.Pos(4) // 'd' 的偏移量
   position := fset.Position(pos)
   fmt.Println(position) // 输出: test.txt:2:1，而不是 test.txt:1:0
   ```

2. **偏移量从 0 开始:** `Offset` 字段是从 0 开始计数的，表示字节在文件中的位置。

3. **`NoPos` 的使用:**  `NoPos` 应该用于表示一个无效或未知的源代码位置。不应该将其与文件中的实际位置混淆。

   ```go
   var p token.Position
   fmt.Println(p.IsValid())      // 输出: false

   p = token.NoPos
   fmt.Println(p.IsValid())      // 输出: false
   ```

4. **理解 `PositionFor` 的 `adjusted` 参数:**  `PositionFor` 方法的第二个参数 `adjusted` 控制是否考虑 `//line` 注释。如果设置为 `true`，则会返回调整后的文件名和行号。如果设置为 `false`，则返回原始的位置信息。忘记区分这两种情况可能导致错误。

   ```go
   src := []byte(`//line other.go:10
   package main
   `)
   fset := token.NewFileSet()
   file := fset.AddFile("test.go", 1, len(src))
   file.SetLinesForContent(src)
   pos := file.Pos(1) // 'p' 的位置

   unadjusted := fset.PositionFor(pos, false)
   fmt.Println(unadjusted) // 输出: test.go:2:5

   adjusted := fset.PositionFor(pos, true)
   fmt.Println(adjusted)   // 输出: other.go:10:1
   ```

总而言之，`go/token/position_test.go` 文件详细测试了 Go 语言中源代码位置表示和管理的核心功能，确保了编译器和相关工具能够准确地跟踪和报告代码位置信息。理解这些测试用例有助于开发者正确使用 `go/token` 包。

### 提示词
```
这是路径为go/src/go/token/position_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token

import (
	"fmt"
	"math/rand"
	"slices"
	"sync"
	"testing"
)

func checkPos(t *testing.T, msg string, got, want Position) {
	if got.Filename != want.Filename {
		t.Errorf("%s: got filename = %q; want %q", msg, got.Filename, want.Filename)
	}
	if got.Offset != want.Offset {
		t.Errorf("%s: got offset = %d; want %d", msg, got.Offset, want.Offset)
	}
	if got.Line != want.Line {
		t.Errorf("%s: got line = %d; want %d", msg, got.Line, want.Line)
	}
	if got.Column != want.Column {
		t.Errorf("%s: got column = %d; want %d", msg, got.Column, want.Column)
	}
}

func TestNoPos(t *testing.T) {
	if NoPos.IsValid() {
		t.Errorf("NoPos should not be valid")
	}
	var fset *FileSet
	checkPos(t, "nil NoPos", fset.Position(NoPos), Position{})
	fset = NewFileSet()
	checkPos(t, "fset NoPos", fset.Position(NoPos), Position{})
}

var tests = []struct {
	filename string
	source   []byte // may be nil
	size     int
	lines    []int
}{
	{"a", []byte{}, 0, []int{}},
	{"b", []byte("01234"), 5, []int{0}},
	{"c", []byte("\n\n\n\n\n\n\n\n\n"), 9, []int{0, 1, 2, 3, 4, 5, 6, 7, 8}},
	{"d", nil, 100, []int{0, 5, 10, 20, 30, 70, 71, 72, 80, 85, 90, 99}},
	{"e", nil, 777, []int{0, 80, 100, 120, 130, 180, 267, 455, 500, 567, 620}},
	{"f", []byte("package p\n\nimport \"fmt\""), 23, []int{0, 10, 11}},
	{"g", []byte("package p\n\nimport \"fmt\"\n"), 24, []int{0, 10, 11}},
	{"h", []byte("package p\n\nimport \"fmt\"\n "), 25, []int{0, 10, 11, 24}},
}

func linecol(lines []int, offs int) (int, int) {
	prevLineOffs := 0
	for line, lineOffs := range lines {
		if offs < lineOffs {
			return line, offs - prevLineOffs + 1
		}
		prevLineOffs = lineOffs
	}
	return len(lines), offs - prevLineOffs + 1
}

func verifyPositions(t *testing.T, fset *FileSet, f *File, lines []int) {
	for offs := 0; offs < f.Size(); offs++ {
		p := f.Pos(offs)
		offs2 := f.Offset(p)
		if offs2 != offs {
			t.Errorf("%s, Offset: got offset %d; want %d", f.Name(), offs2, offs)
		}
		line, col := linecol(lines, offs)
		msg := fmt.Sprintf("%s (offs = %d, p = %d)", f.Name(), offs, p)
		checkPos(t, msg, f.Position(f.Pos(offs)), Position{f.Name(), offs, line, col})
		checkPos(t, msg, fset.Position(p), Position{f.Name(), offs, line, col})
	}
}

func makeTestSource(size int, lines []int) []byte {
	src := make([]byte, size)
	for _, offs := range lines {
		if offs > 0 {
			src[offs-1] = '\n'
		}
	}
	return src
}

func TestPositions(t *testing.T) {
	const delta = 7 // a non-zero base offset increment
	fset := NewFileSet()
	for _, test := range tests {
		// verify consistency of test case
		if test.source != nil && len(test.source) != test.size {
			t.Errorf("%s: inconsistent test case: got file size %d; want %d", test.filename, len(test.source), test.size)
		}

		// add file and verify name and size
		f := fset.AddFile(test.filename, fset.Base()+delta, test.size)
		if f.Name() != test.filename {
			t.Errorf("got filename %q; want %q", f.Name(), test.filename)
		}
		if f.Size() != test.size {
			t.Errorf("%s: got file size %d; want %d", f.Name(), f.Size(), test.size)
		}
		if fset.File(f.Pos(0)) != f {
			t.Errorf("%s: f.Pos(0) was not found in f", f.Name())
		}

		// add lines individually and verify all positions
		for i, offset := range test.lines {
			f.AddLine(offset)
			if f.LineCount() != i+1 {
				t.Errorf("%s, AddLine: got line count %d; want %d", f.Name(), f.LineCount(), i+1)
			}
			// adding the same offset again should be ignored
			f.AddLine(offset)
			if f.LineCount() != i+1 {
				t.Errorf("%s, AddLine: got unchanged line count %d; want %d", f.Name(), f.LineCount(), i+1)
			}
			verifyPositions(t, fset, f, test.lines[0:i+1])
		}

		// add lines with SetLines and verify all positions
		if ok := f.SetLines(test.lines); !ok {
			t.Errorf("%s: SetLines failed", f.Name())
		}
		if f.LineCount() != len(test.lines) {
			t.Errorf("%s, SetLines: got line count %d; want %d", f.Name(), f.LineCount(), len(test.lines))
		}
		if !slices.Equal(f.Lines(), test.lines) {
			t.Errorf("%s, Lines after SetLines(v): got %v; want %v", f.Name(), f.Lines(), test.lines)
		}
		verifyPositions(t, fset, f, test.lines)

		// add lines with SetLinesForContent and verify all positions
		src := test.source
		if src == nil {
			// no test source available - create one from scratch
			src = makeTestSource(test.size, test.lines)
		}
		f.SetLinesForContent(src)
		if f.LineCount() != len(test.lines) {
			t.Errorf("%s, SetLinesForContent: got line count %d; want %d", f.Name(), f.LineCount(), len(test.lines))
		}
		verifyPositions(t, fset, f, test.lines)
	}
}

func TestLineInfo(t *testing.T) {
	fset := NewFileSet()
	f := fset.AddFile("foo", fset.Base(), 500)
	lines := []int{0, 42, 77, 100, 210, 220, 277, 300, 333, 401}
	// add lines individually and provide alternative line information
	for _, offs := range lines {
		f.AddLine(offs)
		f.AddLineInfo(offs, "bar", 42)
	}
	// verify positions for all offsets
	for offs := 0; offs <= f.Size(); offs++ {
		p := f.Pos(offs)
		_, col := linecol(lines, offs)
		msg := fmt.Sprintf("%s (offs = %d, p = %d)", f.Name(), offs, p)
		checkPos(t, msg, f.Position(f.Pos(offs)), Position{"bar", offs, 42, col})
		checkPos(t, msg, fset.Position(p), Position{"bar", offs, 42, col})
	}
}

func TestFiles(t *testing.T) {
	fset := NewFileSet()
	for i, test := range tests {
		base := fset.Base()
		if i%2 == 1 {
			// Setting a negative base is equivalent to
			// fset.Base(), so test some of each.
			base = -1
		}
		fset.AddFile(test.filename, base, test.size)
		j := 0
		fset.Iterate(func(f *File) bool {
			if f.Name() != tests[j].filename {
				t.Errorf("got filename = %s; want %s", f.Name(), tests[j].filename)
			}
			j++
			return true
		})
		if j != i+1 {
			t.Errorf("got %d files; want %d", j, i+1)
		}
	}
}

// FileSet.File should return nil if Pos is past the end of the FileSet.
func TestFileSetPastEnd(t *testing.T) {
	fset := NewFileSet()
	for _, test := range tests {
		fset.AddFile(test.filename, fset.Base(), test.size)
	}
	if f := fset.File(Pos(fset.Base())); f != nil {
		t.Errorf("got %v, want nil", f)
	}
}

func TestFileSetCacheUnlikely(t *testing.T) {
	fset := NewFileSet()
	offsets := make(map[string]int)
	for _, test := range tests {
		offsets[test.filename] = fset.Base()
		fset.AddFile(test.filename, fset.Base(), test.size)
	}
	for file, pos := range offsets {
		f := fset.File(Pos(pos))
		if f.Name() != file {
			t.Errorf("got %q at position %d, want %q", f.Name(), pos, file)
		}
	}
}

// issue 4345. Test that concurrent use of FileSet.Pos does not trigger a
// race in the FileSet position cache.
func TestFileSetRace(t *testing.T) {
	fset := NewFileSet()
	for i := 0; i < 100; i++ {
		fset.AddFile(fmt.Sprintf("file-%d", i), fset.Base(), 1031)
	}
	max := int32(fset.Base())
	var stop sync.WaitGroup
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 2; i++ {
		r := rand.New(rand.NewSource(r.Int63()))
		stop.Add(1)
		go func() {
			for i := 0; i < 1000; i++ {
				fset.Position(Pos(r.Int31n(max)))
			}
			stop.Done()
		}()
	}
	stop.Wait()
}

// issue 16548. Test that concurrent use of File.AddLine and FileSet.PositionFor
// does not trigger a race in the FileSet position cache.
func TestFileSetRace2(t *testing.T) {
	const N = 1e3
	var (
		fset = NewFileSet()
		file = fset.AddFile("", -1, N)
		ch   = make(chan int, 2)
	)

	go func() {
		for i := 0; i < N; i++ {
			file.AddLine(i)
		}
		ch <- 1
	}()

	go func() {
		pos := file.Pos(0)
		for i := 0; i < N; i++ {
			fset.PositionFor(pos, false)
		}
		ch <- 1
	}()

	<-ch
	<-ch
}

func TestPositionFor(t *testing.T) {
	src := []byte(`
foo
b
ar
//line :100
foobar
//line bar:3
done
`)

	const filename = "foo"
	fset := NewFileSet()
	f := fset.AddFile(filename, fset.Base(), len(src))
	f.SetLinesForContent(src)

	// verify position info
	for i, offs := range f.lines {
		got1 := f.PositionFor(f.Pos(offs), false)
		got2 := f.PositionFor(f.Pos(offs), true)
		got3 := f.Position(f.Pos(offs))
		want := Position{filename, offs, i + 1, 1}
		checkPos(t, "1. PositionFor unadjusted", got1, want)
		checkPos(t, "1. PositionFor adjusted", got2, want)
		checkPos(t, "1. Position", got3, want)
	}

	// manually add //line info on lines l1, l2
	const l1, l2 = 5, 7
	f.AddLineInfo(f.lines[l1-1], "", 100)
	f.AddLineInfo(f.lines[l2-1], "bar", 3)

	// unadjusted position info must remain unchanged
	for i, offs := range f.lines {
		got1 := f.PositionFor(f.Pos(offs), false)
		want := Position{filename, offs, i + 1, 1}
		checkPos(t, "2. PositionFor unadjusted", got1, want)
	}

	// adjusted position info should have changed
	for i, offs := range f.lines {
		got2 := f.PositionFor(f.Pos(offs), true)
		got3 := f.Position(f.Pos(offs))
		want := Position{filename, offs, i + 1, 1}
		// manually compute wanted filename and line
		line := want.Line
		if i+1 >= l1 {
			want.Filename = ""
			want.Line = line - l1 + 100
		}
		if i+1 >= l2 {
			want.Filename = "bar"
			want.Line = line - l2 + 3
		}
		checkPos(t, "3. PositionFor adjusted", got2, want)
		checkPos(t, "3. Position", got3, want)
	}
}

func TestLineStart(t *testing.T) {
	const src = "one\ntwo\nthree\n"
	fset := NewFileSet()
	f := fset.AddFile("input", -1, len(src))
	f.SetLinesForContent([]byte(src))

	for line := 1; line <= 3; line++ {
		pos := f.LineStart(line)
		position := fset.Position(pos)
		if position.Line != line || position.Column != 1 {
			t.Errorf("LineStart(%d) returned wrong pos %d: %s", line, pos, position)
		}
	}
}

func TestRemoveFile(t *testing.T) {
	contentA := []byte("this\nis\nfileA")
	contentB := []byte("this\nis\nfileB")
	fset := NewFileSet()
	a := fset.AddFile("fileA", -1, len(contentA))
	a.SetLinesForContent(contentA)
	b := fset.AddFile("fileB", -1, len(contentB))
	b.SetLinesForContent(contentB)

	checkPos := func(pos Pos, want string) {
		if got := fset.Position(pos).String(); got != want {
			t.Errorf("Position(%d) = %s, want %s", pos, got, want)
		}
	}
	checkNumFiles := func(want int) {
		got := 0
		fset.Iterate(func(*File) bool { got++; return true })
		if got != want {
			t.Errorf("Iterate called %d times, want %d", got, want)
		}
	}

	apos3 := a.Pos(3)
	bpos3 := b.Pos(3)
	checkPos(apos3, "fileA:1:4")
	checkPos(bpos3, "fileB:1:4")
	checkNumFiles(2)

	// After removal, queries on fileA fail.
	fset.RemoveFile(a)
	checkPos(apos3, "-")
	checkPos(bpos3, "fileB:1:4")
	checkNumFiles(1)

	// idempotent / no effect
	fset.RemoveFile(a)
	checkPos(apos3, "-")
	checkPos(bpos3, "fileB:1:4")
	checkNumFiles(1)
}

func TestFileAddLineColumnInfo(t *testing.T) {
	const (
		filename = "test.go"
		filesize = 100
	)

	tests := []struct {
		name  string
		infos []lineInfo
		want  []lineInfo
	}{
		{
			name: "normal",
			infos: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
				{Offset: 50, Filename: filename, Line: 3, Column: 1},
				{Offset: 80, Filename: filename, Line: 4, Column: 2},
			},
			want: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
				{Offset: 50, Filename: filename, Line: 3, Column: 1},
				{Offset: 80, Filename: filename, Line: 4, Column: 2},
			},
		},
		{
			name: "offset1 == file size",
			infos: []lineInfo{
				{Offset: filesize, Filename: filename, Line: 2, Column: 1},
			},
			want: nil,
		},
		{
			name: "offset1 > file size",
			infos: []lineInfo{
				{Offset: filesize + 1, Filename: filename, Line: 2, Column: 1},
			},
			want: nil,
		},
		{
			name: "offset2 == file size",
			infos: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
				{Offset: filesize, Filename: filename, Line: 3, Column: 1},
			},
			want: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
			},
		},
		{
			name: "offset2 > file size",
			infos: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
				{Offset: filesize + 1, Filename: filename, Line: 3, Column: 1},
			},
			want: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
			},
		},
		{
			name: "offset2 == offset1",
			infos: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
				{Offset: 10, Filename: filename, Line: 3, Column: 1},
			},
			want: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
			},
		},
		{
			name: "offset2 < offset1",
			infos: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
				{Offset: 9, Filename: filename, Line: 3, Column: 1},
			},
			want: []lineInfo{
				{Offset: 10, Filename: filename, Line: 2, Column: 1},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fs := NewFileSet()
			f := fs.AddFile(filename, -1, filesize)
			for _, info := range test.infos {
				f.AddLineColumnInfo(info.Offset, info.Filename, info.Line, info.Column)
			}
			if !slices.Equal(f.infos, test.want) {
				t.Errorf("\ngot %+v, \nwant %+v", f.infos, test.want)
			}
		})
	}
}

func TestIssue57490(t *testing.T) {
	// If debug is set, this test is expected to panic.
	if debug {
		defer func() {
			if recover() == nil {
				t.Errorf("got no panic")
			}
		}()
	}

	const fsize = 5
	fset := NewFileSet()
	base := fset.Base()
	f := fset.AddFile("f", base, fsize)

	// out-of-bounds positions must not lead to a panic when calling f.Offset
	if got := f.Offset(NoPos); got != 0 {
		t.Errorf("offset = %d, want %d", got, 0)
	}
	if got := f.Offset(Pos(-1)); got != 0 {
		t.Errorf("offset = %d, want %d", got, 0)
	}
	if got := f.Offset(Pos(base + fsize + 1)); got != fsize {
		t.Errorf("offset = %d, want %d", got, fsize)
	}

	// out-of-bounds offsets must not lead to a panic when calling f.Pos
	if got := f.Pos(-1); got != Pos(base) {
		t.Errorf("pos = %d, want %d", got, base)
	}
	if got := f.Pos(fsize + 1); got != Pos(base+fsize) {
		t.Errorf("pos = %d, want %d", got, base+fsize)
	}

	// out-of-bounds Pos values must not lead to a panic when calling f.Position
	want := fmt.Sprintf("%s:1:1", f.Name())
	if got := f.Position(Pos(-1)).String(); got != want {
		t.Errorf("position = %s, want %s", got, want)
	}
	want = fmt.Sprintf("%s:1:%d", f.Name(), fsize+1)
	if got := f.Position(Pos(fsize + 1)).String(); got != want {
		t.Errorf("position = %s, want %s", got, want)
	}

	// check invariants
	const xsize = fsize + 5
	for offset := -xsize; offset < xsize; offset++ {
		want1 := f.Offset(Pos(f.base + offset))
		if got := f.Offset(f.Pos(offset)); got != want1 {
			t.Errorf("offset = %d, want %d", got, want1)
		}

		want2 := f.Pos(offset)
		if got := f.Pos(f.Offset(want2)); got != want2 {
			t.Errorf("pos = %d, want %d", got, want2)
		}
	}
}
```