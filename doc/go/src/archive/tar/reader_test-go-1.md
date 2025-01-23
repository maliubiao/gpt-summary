Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Context:** The prompt states this is part of `go/src/archive/tar/reader_test.go`. This immediately tells us this is test code for the `archive/tar` package, specifically focusing on the reading functionality. The "part 2 of 2" suggests we've already analyzed some other part of this test file.

2. **Identify the Primary Function Under Test:** Skimming the code reveals several test functions: `TestReadGNUSparsePAXHeaders`, `TestFileReader`, and `TestInsecurePaths`, `TestDisableInsecurePathCheck`. These are the main subjects of the tests.

3. **Analyze Individual Test Functions:**

    * **`TestReadGNUSparsePAXHeaders`:**
        * **Goal:** The name strongly suggests it tests the parsing of sparse file headers in the PAX format. Sparse files are files with "holes" – large sections of zero bytes that aren't actually stored on disk.
        * **Mechanism:** It sets up a series of test cases (`vectors`). Each test case defines:
            * `inputHdrs`: A map simulating PAX headers related to sparse files (like `paxGNUSparseNumBlocks`, `paxGNUSparseMap`, etc.).
            * `inputData`:  Optional data simulating the actual sparse data following the header, particularly relevant for PAX format version 1.
            * `wantMap`: The expected `sparseDatas` structure, representing the blocks of actual data within the sparse file.
            * `wantSize`, `wantName`: Expected values for the file's size and name after processing the headers.
            * `wantErr`: The expected error, if any.
        * **How it works:** The test creates a `Reader`, feeds it simulated headers and data, calls `readGNUSparsePAXHeaders`, and then asserts the parsed `sparseDatas`, `Header.Size`, `Header.Name`, and any returned error match the expected values.
        * **Key Observation:**  The test handles both PAX format 0 (using `paxGNUSparseNumBlocks` and `paxGNUSparseMap`) and PAX format 1 (using `paxGNUSparseMajor` and `paxGNUSparseMinor` and reading data from the stream).

    * **`TestFileReader`:**
        * **Goal:**  Tests the functionality of different `fileReader` implementations, specifically `regFileReader` (for regular files) and `sparseFileReader` (for sparse files).
        * **Mechanism:** It uses a `vectors` structure again. Each test case defines:
            * `maker`:  Specifies how to create the `fileReader` (either as a regular file with content and size, or as a sparse file with underlying regular file data, sparse data map, and total size).
            * `tests`: A slice of test actions (`testRead`, `testWriteTo`, `testRemaining`).
        * **Test Actions:**
            * `testRead`: Simulates reading a specific number of bytes and verifies the output and any error.
            * `testWriteTo`: Simulates writing to a test file (using `testFile`) and verifies the number of bytes written and any error.
            * `testRemaining`: Checks the logical (total file size) and physical (actual data size) remaining bytes.
        * **Key Observation:**  This test comprehensively covers reading and "writing to" (simulated write) both regular and sparse file data, including edge cases and error conditions.

    * **`TestInsecurePaths`:**
        * **Goal:** Tests the security mechanism that prevents extracting files to potentially dangerous paths (like those containing `..`).
        * **Mechanism:** It sets the `GODEBUG` environment variable to disable the insecure path check (`tarinsecurepath=0`). It then creates a tar archive with a file having an insecure path. It uses `tr.Next()` to read the header and expects an `ErrInsecurePath` error. It also verifies that subsequent calls to `tr.Next()` work for secure paths, showing the error isn't sticky.

    * **`TestDisableInsecurePathCheck`:**
        * **Goal:** Tests the ability to disable the insecure path check.
        * **Mechanism:** It sets the `GODEBUG` environment variable to enable the insecure path check (`tarinsecurepath=1`). It creates a tar archive with an insecure path and verifies that `tr.Next()` reads the header without an error.

4. **Identify Go Language Features:**

    * **Table-driven testing:** The extensive use of `vectors` slices to define test cases is a classic Go testing pattern for making tests organized and easier to extend.
    * **Interfaces and Polymorphism:** The `fileReader` interface and its concrete implementations (`regFileReader`, `sparseFileReader`) demonstrate polymorphism. The test code works with the `fileReader` interface without needing to know the specific implementation.
    * **Error Handling:** The tests explicitly check for expected errors using `errors.Is` or direct comparison. Custom errors like `ErrHeader`, `ErrInsecurePath`, `errMissData`, `errUnrefData` are defined elsewhere in the package.
    * **Environment Variables for Configuration:** The use of the `GODEBUG` environment variable to control the insecure path check is a way to configure behavior without code changes.
    * **`io.Reader` and `io.WriterTo` interfaces:** The code utilizes these standard interfaces for reading and writing data streams.

5. **Synthesize the Functionality:** Based on the analysis of the individual tests, we can summarize the functionality being tested.

6. **Illustrate with Code Examples:**  Create concise Go code snippets that demonstrate the key functionalities, including setting up a `Reader`, handling headers, and reading data, with specific focus on sparse file scenarios. Include assumed input and output to make the examples concrete.

7. **Address Command-line Arguments:** Focus on the `GODEBUG` environment variable used to control the insecure path check, explaining its purpose and values.

8. **Identify Common Mistakes:** Think about scenarios where a user might misuse the `archive/tar` package, such as forgetting to handle errors, not understanding sparse file handling, or being unaware of the insecure path check.

9. **Consolidate and Refine:** Organize the findings into a clear and concise answer, using appropriate terminology and code formatting. Make sure the examples are easy to understand and the explanations are accurate. Pay attention to the "part 2 of 2" and provide a final summary.
好的，这是对提供的 Go 语言代码片段的功能归纳：

这段代码是 `go/src/archive/tar/reader_test.go` 文件的一部分，它主要针对 `archive/tar` 包中的 `Reader` 类型的相关功能进行测试，特别是关于读取 tar 归档文件头信息和文件内容的部分。

具体来说，这段代码测试了以下几个方面的功能：

1. **读取并解析 GNU 扩展的 PAX 稀疏文件头信息 (GNU Sparse Headers in PAX format):**
   - 测试了 `readGNUSparsePAXHeaders` 函数，该函数负责从 PAX 扩展头中解析出稀疏文件的元数据，包括数据块的偏移量和大小。
   - 涵盖了 PAX 格式 0 和 1 的解析，通过 `paxGNUSparseNumBlocks` 和 `paxGNUSparseMap` (格式 0)，以及 `paxGNUSparseMajor` 和 `paxGNUSparseMinor` (格式 1) 来识别和解析稀疏信息。
   - 验证了在解析过程中，对于不符合规范的头信息会返回相应的错误 (`ErrHeader`)。
   - 测试了在 PAX 格式 1 中，如何读取后续的数据流来获取稀疏映射信息。

2. **`fileReader` 接口及其实现 (`regFileReader` 和 `sparseFileReader`) 的功能:**
   - 测试了读取普通文件内容 (`regFileReader`) 和稀疏文件内容 (`sparseFileReader`) 的功能。
   - 重点测试了 `Read` 方法的行为，包括读取指定数量的字节，以及在遇到文件末尾或意外情况时的错误处理 (`io.EOF`, `io.ErrUnexpectedEOF`)。
   - 测试了 `WriteTo` 方法，模拟将 `fileReader` 的内容写入到另一个 `io.Writer` 的过程，用于验证数据是否正确读取。
   - 验证了 `logicalRemaining` 和 `physicalRemaining` 方法，用于获取逻辑剩余大小（声明的文件总大小）和物理剩余大小（实际剩余数据大小），这在处理稀疏文件时尤为重要。

3. **安全路径检查机制:**
   - 测试了当尝试读取包含不安全路径（例如包含 `..` 的路径）的文件时，是否会返回 `ErrInsecurePath` 错误。
   - 验证了可以通过设置 `GODEBUG` 环境变量 `tarinsecurepath=0` 来启用此安全检查。

4. **禁用安全路径检查机制:**
   - 测试了可以通过设置 `GODEBUG` 环境变量 `tarinsecurepath=1` 来禁用安全路径检查，允许读取包含不安全路径的文件。

**总结来说，这段代码主要测试了 `archive/tar` 包中 `Reader` 类型在处理不同类型的 tar 文件（包括包含 GNU 扩展 PAX 稀疏文件头信息的 tar 文件）时，读取文件头信息和文件内容的功能，以及相关的安全机制。**

这段代码的核心目的是确保 `archive/tar` 包能够正确、安全地解析和读取各种格式的 tar 归档文件。通过大量的测试用例，覆盖了正常情况和各种异常情况，保证了代码的健壮性和可靠性。

### 提示词
```
这是路径为go/src/archive/tar/reader_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
map[string]string
		wantMap   sparseDatas
		wantSize  int64
		wantName  string
		wantErr   error
	}{{
		inputHdrs: nil,
		wantErr:   nil,
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseNumBlocks: strconv.FormatInt(math.MaxInt64, 10),
			paxGNUSparseMap:       "0,1,2,3",
		},
		wantErr: ErrHeader,
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseNumBlocks: "4\x00",
			paxGNUSparseMap:       "0,1,2,3",
		},
		wantErr: ErrHeader,
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseNumBlocks: "4",
			paxGNUSparseMap:       "0,1,2,3",
		},
		wantErr: ErrHeader,
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseNumBlocks: "2",
			paxGNUSparseMap:       "0,1,2,3",
		},
		wantMap: sparseDatas{{0, 1}, {2, 3}},
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseNumBlocks: "2",
			paxGNUSparseMap:       "0, 1,2,3",
		},
		wantErr: ErrHeader,
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseNumBlocks: "2",
			paxGNUSparseMap:       "0,1,02,3",
			paxGNUSparseRealSize:  "4321",
		},
		wantMap:  sparseDatas{{0, 1}, {2, 3}},
		wantSize: 4321,
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseNumBlocks: "2",
			paxGNUSparseMap:       "0,one1,2,3",
		},
		wantErr: ErrHeader,
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseMajor:     "0",
			paxGNUSparseMinor:     "0",
			paxGNUSparseNumBlocks: "2",
			paxGNUSparseMap:       "0,1,2,3",
			paxGNUSparseSize:      "1234",
			paxGNUSparseRealSize:  "4321",
			paxGNUSparseName:      "realname",
		},
		wantMap:  sparseDatas{{0, 1}, {2, 3}},
		wantSize: 1234,
		wantName: "realname",
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseMajor:     "0",
			paxGNUSparseMinor:     "0",
			paxGNUSparseNumBlocks: "1",
			paxGNUSparseMap:       "10737418240,512",
			paxGNUSparseSize:      "10737418240",
			paxGNUSparseName:      "realname",
		},
		wantMap:  sparseDatas{{10737418240, 512}},
		wantSize: 10737418240,
		wantName: "realname",
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseMajor:     "0",
			paxGNUSparseMinor:     "0",
			paxGNUSparseNumBlocks: "0",
			paxGNUSparseMap:       "",
		},
		wantMap: sparseDatas{},
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseMajor:     "0",
			paxGNUSparseMinor:     "1",
			paxGNUSparseNumBlocks: "4",
			paxGNUSparseMap:       "0,5,10,5,20,5,30,5",
		},
		wantMap: sparseDatas{{0, 5}, {10, 5}, {20, 5}, {30, 5}},
	}, {
		inputHdrs: map[string]string{
			paxGNUSparseMajor:     "1",
			paxGNUSparseMinor:     "0",
			paxGNUSparseNumBlocks: "4",
			paxGNUSparseMap:       "0,5,10,5,20,5,30,5",
		},
		wantErr: io.ErrUnexpectedEOF,
	}, {
		inputData: padInput("0\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantMap:   sparseDatas{},
	}, {
		inputData: padInput("0\n")[:blockSize-1] + "#",
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantMap:   sparseDatas{},
	}, {
		inputData: padInput("0"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantErr:   io.ErrUnexpectedEOF,
	}, {
		inputData: padInput("ab\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantErr:   ErrHeader,
	}, {
		inputData: padInput("1\n2\n3\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantMap:   sparseDatas{{2, 3}},
	}, {
		inputData: padInput("1\n2\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantErr:   io.ErrUnexpectedEOF,
	}, {
		inputData: padInput("1\n2\n\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantErr:   ErrHeader,
	}, {
		inputData: string(zeroBlock[:]) + padInput("0\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantErr:   ErrHeader,
	}, {
		inputData: strings.Repeat("0", blockSize) + padInput("1\n5\n1\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantMap:   sparseDatas{{5, 1}},
	}, {
		inputData: padInput(fmt.Sprintf("%d\n", int64(math.MaxInt64))),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantErr:   ErrHeader,
	}, {
		inputData: padInput(strings.Repeat("0", 300) + "1\n" + strings.Repeat("0", 1000) + "5\n" + strings.Repeat("0", 800) + "2\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantMap:   sparseDatas{{5, 2}},
	}, {
		inputData: padInput("2\n10737418240\n512\n21474836480\n512\n"),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantMap:   sparseDatas{{10737418240, 512}, {21474836480, 512}},
	}, {
		inputData: padInput("100\n" + func() string {
			var ss []string
			for i := 0; i < 100; i++ {
				ss = append(ss, fmt.Sprintf("%d\n%d\n", int64(i)<<30, 512))
			}
			return strings.Join(ss, "")
		}()),
		inputHdrs: map[string]string{paxGNUSparseMajor: "1", paxGNUSparseMinor: "0"},
		wantMap: func() (spd sparseDatas) {
			for i := 0; i < 100; i++ {
				spd = append(spd, sparseEntry{int64(i) << 30, 512})
			}
			return spd
		}(),
	}}

	for i, v := range vectors {
		var hdr Header
		hdr.PAXRecords = v.inputHdrs
		r := strings.NewReader(v.inputData + "#") // Add canary byte
		tr := Reader{curr: &regFileReader{r, int64(r.Len())}}
		got, err := tr.readGNUSparsePAXHeaders(&hdr)
		if !slices.Equal(got, v.wantMap) {
			t.Errorf("test %d, readGNUSparsePAXHeaders(): got %v, want %v", i, got, v.wantMap)
		}
		if err != v.wantErr {
			t.Errorf("test %d, readGNUSparsePAXHeaders() = %v, want %v", i, err, v.wantErr)
		}
		if hdr.Size != v.wantSize {
			t.Errorf("test %d, Header.Size = %d, want %d", i, hdr.Size, v.wantSize)
		}
		if hdr.Name != v.wantName {
			t.Errorf("test %d, Header.Name = %s, want %s", i, hdr.Name, v.wantName)
		}
		if v.wantErr == nil && r.Len() == 0 {
			t.Errorf("test %d, canary byte unexpectedly consumed", i)
		}
	}
}

// testNonEmptyReader wraps an io.Reader and ensures that
// Read is never called with an empty buffer.
type testNonEmptyReader struct{ io.Reader }

func (r testNonEmptyReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, errors.New("unexpected empty Read call")
	}
	return r.Reader.Read(b)
}

func TestFileReader(t *testing.T) {
	type (
		testRead struct { // Read(cnt) == (wantStr, wantErr)
			cnt     int
			wantStr string
			wantErr error
		}
		testWriteTo struct { // WriteTo(testFile{ops}) == (wantCnt, wantErr)
			ops     fileOps
			wantCnt int64
			wantErr error
		}
		testRemaining struct { // logicalRemaining() == wantLCnt, physicalRemaining() == wantPCnt
			wantLCnt int64
			wantPCnt int64
		}
		testFnc any // testRead | testWriteTo | testRemaining
	)

	type (
		makeReg struct {
			str  string
			size int64
		}
		makeSparse struct {
			makeReg makeReg
			spd     sparseDatas
			size    int64
		}
		fileMaker any // makeReg | makeSparse
	)

	vectors := []struct {
		maker fileMaker
		tests []testFnc
	}{{
		maker: makeReg{"", 0},
		tests: []testFnc{
			testRemaining{0, 0},
			testRead{0, "", io.EOF},
			testRead{1, "", io.EOF},
			testWriteTo{nil, 0, nil},
			testRemaining{0, 0},
		},
	}, {
		maker: makeReg{"", 1},
		tests: []testFnc{
			testRemaining{1, 1},
			testRead{5, "", io.ErrUnexpectedEOF},
			testWriteTo{nil, 0, io.ErrUnexpectedEOF},
			testRemaining{1, 1},
		},
	}, {
		maker: makeReg{"hello", 5},
		tests: []testFnc{
			testRemaining{5, 5},
			testRead{5, "hello", io.EOF},
			testRemaining{0, 0},
		},
	}, {
		maker: makeReg{"hello, world", 50},
		tests: []testFnc{
			testRemaining{50, 50},
			testRead{7, "hello, ", nil},
			testRemaining{43, 43},
			testRead{5, "world", nil},
			testRemaining{38, 38},
			testWriteTo{nil, 0, io.ErrUnexpectedEOF},
			testRead{1, "", io.ErrUnexpectedEOF},
			testRemaining{38, 38},
		},
	}, {
		maker: makeReg{"hello, world", 5},
		tests: []testFnc{
			testRemaining{5, 5},
			testRead{0, "", nil},
			testRead{4, "hell", nil},
			testRemaining{1, 1},
			testWriteTo{fileOps{"o"}, 1, nil},
			testRemaining{0, 0},
			testWriteTo{nil, 0, nil},
			testRead{0, "", io.EOF},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{0, 2}, {5, 3}}, 8},
		tests: []testFnc{
			testRemaining{8, 5},
			testRead{3, "ab\x00", nil},
			testRead{10, "\x00\x00cde", io.EOF},
			testRemaining{0, 0},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{0, 2}, {5, 3}}, 8},
		tests: []testFnc{
			testRemaining{8, 5},
			testWriteTo{fileOps{"ab", int64(3), "cde"}, 8, nil},
			testRemaining{0, 0},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{0, 2}, {5, 3}}, 10},
		tests: []testFnc{
			testRemaining{10, 5},
			testRead{100, "ab\x00\x00\x00cde\x00\x00", io.EOF},
			testRemaining{0, 0},
		},
	}, {
		maker: makeSparse{makeReg{"abc", 5}, sparseDatas{{0, 2}, {5, 3}}, 10},
		tests: []testFnc{
			testRemaining{10, 5},
			testRead{100, "ab\x00\x00\x00c", io.ErrUnexpectedEOF},
			testRemaining{4, 2},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{1, 3}, {6, 2}}, 8},
		tests: []testFnc{
			testRemaining{8, 5},
			testRead{8, "\x00abc\x00\x00de", io.EOF},
			testRemaining{0, 0},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{1, 3}, {6, 0}, {6, 0}, {6, 2}}, 8},
		tests: []testFnc{
			testRemaining{8, 5},
			testRead{8, "\x00abc\x00\x00de", io.EOF},
			testRemaining{0, 0},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{1, 3}, {6, 0}, {6, 0}, {6, 2}}, 8},
		tests: []testFnc{
			testRemaining{8, 5},
			testWriteTo{fileOps{int64(1), "abc", int64(2), "de"}, 8, nil},
			testRemaining{0, 0},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{1, 3}, {6, 2}}, 10},
		tests: []testFnc{
			testRead{100, "\x00abc\x00\x00de\x00\x00", io.EOF},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{1, 3}, {6, 2}}, 10},
		tests: []testFnc{
			testWriteTo{fileOps{int64(1), "abc", int64(2), "de", int64(1), "\x00"}, 10, nil},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{1, 3}, {6, 2}, {8, 0}, {8, 0}, {8, 0}, {8, 0}}, 10},
		tests: []testFnc{
			testRead{100, "\x00abc\x00\x00de\x00\x00", io.EOF},
		},
	}, {
		maker: makeSparse{makeReg{"", 0}, sparseDatas{}, 2},
		tests: []testFnc{
			testRead{100, "\x00\x00", io.EOF},
		},
	}, {
		maker: makeSparse{makeReg{"", 8}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRead{100, "\x00", io.ErrUnexpectedEOF},
		},
	}, {
		maker: makeSparse{makeReg{"ab", 2}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRead{100, "\x00ab", errMissData},
		},
	}, {
		maker: makeSparse{makeReg{"ab", 8}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRead{100, "\x00ab", io.ErrUnexpectedEOF},
		},
	}, {
		maker: makeSparse{makeReg{"abc", 3}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRead{100, "\x00abc\x00\x00", errMissData},
		},
	}, {
		maker: makeSparse{makeReg{"abc", 8}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRead{100, "\x00abc\x00\x00", io.ErrUnexpectedEOF},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRead{100, "\x00abc\x00\x00de", errMissData},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 5}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testWriteTo{fileOps{int64(1), "abc", int64(2), "de"}, 8, errMissData},
		},
	}, {
		maker: makeSparse{makeReg{"abcde", 8}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRead{100, "\x00abc\x00\x00de", io.ErrUnexpectedEOF},
		},
	}, {
		maker: makeSparse{makeReg{"abcdefghEXTRA", 13}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRemaining{15, 13},
			testRead{100, "\x00abc\x00\x00defgh\x00\x00\x00\x00", errUnrefData},
			testWriteTo{nil, 0, errUnrefData},
			testRemaining{0, 5},
		},
	}, {
		maker: makeSparse{makeReg{"abcdefghEXTRA", 13}, sparseDatas{{1, 3}, {6, 5}}, 15},
		tests: []testFnc{
			testRemaining{15, 13},
			testWriteTo{fileOps{int64(1), "abc", int64(2), "defgh", int64(4)}, 15, errUnrefData},
			testRead{100, "", errUnrefData},
			testRemaining{0, 5},
		},
	}}

	for i, v := range vectors {
		var fr fileReader
		switch maker := v.maker.(type) {
		case makeReg:
			r := testNonEmptyReader{strings.NewReader(maker.str)}
			fr = &regFileReader{r, maker.size}
		case makeSparse:
			if !validateSparseEntries(maker.spd, maker.size) {
				t.Fatalf("invalid sparse map: %v", maker.spd)
			}
			sph := invertSparseEntries(maker.spd, maker.size)
			r := testNonEmptyReader{strings.NewReader(maker.makeReg.str)}
			fr = &regFileReader{r, maker.makeReg.size}
			fr = &sparseFileReader{fr, sph, 0}
		default:
			t.Fatalf("test %d, unknown make operation: %T", i, maker)
		}

		for j, tf := range v.tests {
			switch tf := tf.(type) {
			case testRead:
				b := make([]byte, tf.cnt)
				n, err := fr.Read(b)
				if got := string(b[:n]); got != tf.wantStr || err != tf.wantErr {
					t.Errorf("test %d.%d, Read(%d):\ngot  (%q, %v)\nwant (%q, %v)", i, j, tf.cnt, got, err, tf.wantStr, tf.wantErr)
				}
			case testWriteTo:
				f := &testFile{ops: tf.ops}
				got, err := fr.WriteTo(f)
				if _, ok := err.(testError); ok {
					t.Errorf("test %d.%d, WriteTo(): %v", i, j, err)
				} else if got != tf.wantCnt || err != tf.wantErr {
					t.Errorf("test %d.%d, WriteTo() = (%d, %v), want (%d, %v)", i, j, got, err, tf.wantCnt, tf.wantErr)
				}
				if len(f.ops) > 0 {
					t.Errorf("test %d.%d, expected %d more operations", i, j, len(f.ops))
				}
			case testRemaining:
				if got := fr.logicalRemaining(); got != tf.wantLCnt {
					t.Errorf("test %d.%d, logicalRemaining() = %d, want %d", i, j, got, tf.wantLCnt)
				}
				if got := fr.physicalRemaining(); got != tf.wantPCnt {
					t.Errorf("test %d.%d, physicalRemaining() = %d, want %d", i, j, got, tf.wantPCnt)
				}
			default:
				t.Fatalf("test %d.%d, unknown test operation: %T", i, j, tf)
			}
		}
	}
}

func TestInsecurePaths(t *testing.T) {
	t.Setenv("GODEBUG", "tarinsecurepath=0")
	for _, path := range []string{
		"../foo",
		"/foo",
		"a/b/../../../c",
	} {
		var buf bytes.Buffer
		tw := NewWriter(&buf)
		tw.WriteHeader(&Header{
			Name: path,
		})
		const securePath = "secure"
		tw.WriteHeader(&Header{
			Name: securePath,
		})
		tw.Close()

		tr := NewReader(&buf)
		h, err := tr.Next()
		if err != ErrInsecurePath {
			t.Errorf("tr.Next for file %q: got err %v, want ErrInsecurePath", path, err)
			continue
		}
		if h.Name != path {
			t.Errorf("tr.Next for file %q: got name %q, want %q", path, h.Name, path)
		}
		// Error should not be sticky.
		h, err = tr.Next()
		if err != nil {
			t.Errorf("tr.Next for file %q: got err %v, want nil", securePath, err)
		}
		if h.Name != securePath {
			t.Errorf("tr.Next for file %q: got name %q, want %q", securePath, h.Name, securePath)
		}
	}
}

func TestDisableInsecurePathCheck(t *testing.T) {
	t.Setenv("GODEBUG", "tarinsecurepath=1")
	var buf bytes.Buffer
	tw := NewWriter(&buf)
	const name = "/foo"
	tw.WriteHeader(&Header{
		Name: name,
	})
	tw.Close()
	tr := NewReader(&buf)
	h, err := tr.Next()
	if err != nil {
		t.Fatalf("tr.Next with tarinsecurepath=1: got err %v, want nil", err)
	}
	if h.Name != name {
		t.Fatalf("tr.Next with tarinsecurepath=1: got name %q, want %q", h.Name, name)
	}
}
```