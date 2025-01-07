Response:
The user wants me to analyze a Go source code file related to reading tar archives.

Here's a plan to address the request:

1. **Identify the core functionality:** The filename `reader_test.go` strongly suggests that this code contains tests for the tar reader implementation.
2. **Analyze the test cases:**  The `TestReader` function appears to be the main focus, iterating through various test files (`.tar`) and comparing the extracted headers and checksums against expected values.
3. **Infer the tested Go features:**  The code uses the `archive/tar` package and tests its ability to parse different tar formats (GNU, PAX, V7, STAR), handle sparse files, extended attributes, and various edge cases like truncated files or invalid headers.
4. **Provide Go code examples:** I can illustrate the usage of the `tar.NewReader` and `tar.Reader.Next` functions.
5. **Explain code reasoning (with assumptions):**  For the checksum part, I can assume that the code reads the file content after reading the header and calculates the CRC32 checksum.
6. **Address command-line arguments:** This particular snippet doesn't seem to directly handle command-line arguments. The test cases use predefined files.
7. **Highlight potential pitfalls:**  A common mistake is not handling the `io.EOF` correctly when iterating through tar entries.
8. **Summarize the functionality:**  Based on the analysis, I'll provide a concise summary of the code's purpose.
这是一个Go语言测试文件的部分代码，路径为 `go/src/archive/tar/reader_test.go`。 从文件名和代码内容来看，它的主要功能是 **测试 `archive/tar` 包中 `Reader` 类型的各种功能**。

具体来说，这段代码主要通过以下方式测试 `tar.Reader`:

1. **读取不同格式的tar文件**:  代码定义了一个 `vectors` 结构体切片，其中包含了多个测试用例。每个用例指定了一个 `file` 字段，指向一个实际的 `.tar` 文件（例如 `testdata/gnu.tar`, `testdata/pax.tar` 等），这些文件代表了不同格式的tar归档文件，包括 GNU、PAX、STAR 和 V7 等格式。

2. **验证头部信息 (Headers)**: 每个测试用例还包含了 `headers` 字段，它是一个 `tar.Header` 结构体切片，定义了预期从对应的tar文件中解析出的文件头部信息。测试代码会读取tar文件，并逐个比较解析出的头部信息与预期值是否一致，包括文件名、权限、UID、GID、大小、修改时间、类型标识等。

3. **验证文件内容校验和 (Checksums)**: 部分测试用例还包含 `chksums` 字段，它是一个字符串切片，存储了预期从tar文件中读取的文件内容的 CRC32 校验和。测试代码会在读取文件头部后，计算文件内容的校验和，并与预期值进行比较。

4. **测试错误处理**:  部分测试用例指定了 `err` 字段，用于验证当读取特定的tar文件时，`tar.Reader` 是否会抛出预期的错误，例如 `ErrHeader` (头部错误) 或 `ErrFieldTooLong` (字段过长) 等。

**基于以上分析，可以归纳一下这段代码的功能：**

这段代码是 `archive/tar` 包中 `Reader` 类型的单元测试。它通过读取各种预先准备好的 tar 归档文件，并断言解析出的头部信息、文件内容校验和以及错误处理是否符合预期，从而验证 `tar.Reader` 的正确性和健壮性，确保它可以正确地读取不同格式的 tar 文件，并能处理各种异常情况。

Prompt: 
```
这是路径为go/src/archive/tar/reader_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tar

import (
	"bytes"
	"compress/bzip2"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"maps"
	"math"
	"os"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReader(t *testing.T) {
	vectors := []struct {
		file    string    // Test input file
		headers []*Header // Expected output headers
		chksums []string  // CRC32 checksum of files, leave as nil if not checked
		err     error     // Expected error to occur
	}{{
		file: "testdata/gnu.tar",
		headers: []*Header{{
			Name:     "small.txt",
			Mode:     0640,
			Uid:      73025,
			Gid:      5000,
			Size:     5,
			ModTime:  time.Unix(1244428340, 0),
			Typeflag: '0',
			Uname:    "dsymonds",
			Gname:    "eng",
			Format:   FormatGNU,
		}, {
			Name:     "small2.txt",
			Mode:     0640,
			Uid:      73025,
			Gid:      5000,
			Size:     11,
			ModTime:  time.Unix(1244436044, 0),
			Typeflag: '0',
			Uname:    "dsymonds",
			Gname:    "eng",
			Format:   FormatGNU,
		}},
		chksums: []string{
			"6cbd88fc",
			"ddac04b3",
		},
	}, {
		file: "testdata/sparse-formats.tar",
		headers: []*Header{{
			Name:     "sparse-gnu",
			Mode:     420,
			Uid:      1000,
			Gid:      1000,
			Size:     200,
			ModTime:  time.Unix(1392395740, 0),
			Typeflag: 0x53,
			Linkname: "",
			Uname:    "david",
			Gname:    "david",
			Devmajor: 0,
			Devminor: 0,
			Format:   FormatGNU,
		}, {
			Name:     "sparse-posix-0.0",
			Mode:     420,
			Uid:      1000,
			Gid:      1000,
			Size:     200,
			ModTime:  time.Unix(1392342187, 0),
			Typeflag: 0x30,
			Linkname: "",
			Uname:    "david",
			Gname:    "david",
			Devmajor: 0,
			Devminor: 0,
			PAXRecords: map[string]string{
				"GNU.sparse.size":      "200",
				"GNU.sparse.numblocks": "95",
				"GNU.sparse.map":       "1,1,3,1,5,1,7,1,9,1,11,1,13,1,15,1,17,1,19,1,21,1,23,1,25,1,27,1,29,1,31,1,33,1,35,1,37,1,39,1,41,1,43,1,45,1,47,1,49,1,51,1,53,1,55,1,57,1,59,1,61,1,63,1,65,1,67,1,69,1,71,1,73,1,75,1,77,1,79,1,81,1,83,1,85,1,87,1,89,1,91,1,93,1,95,1,97,1,99,1,101,1,103,1,105,1,107,1,109,1,111,1,113,1,115,1,117,1,119,1,121,1,123,1,125,1,127,1,129,1,131,1,133,1,135,1,137,1,139,1,141,1,143,1,145,1,147,1,149,1,151,1,153,1,155,1,157,1,159,1,161,1,163,1,165,1,167,1,169,1,171,1,173,1,175,1,177,1,179,1,181,1,183,1,185,1,187,1,189,1",
			},
			Format: FormatPAX,
		}, {
			Name:     "sparse-posix-0.1",
			Mode:     420,
			Uid:      1000,
			Gid:      1000,
			Size:     200,
			ModTime:  time.Unix(1392340456, 0),
			Typeflag: 0x30,
			Linkname: "",
			Uname:    "david",
			Gname:    "david",
			Devmajor: 0,
			Devminor: 0,
			PAXRecords: map[string]string{
				"GNU.sparse.size":      "200",
				"GNU.sparse.numblocks": "95",
				"GNU.sparse.map":       "1,1,3,1,5,1,7,1,9,1,11,1,13,1,15,1,17,1,19,1,21,1,23,1,25,1,27,1,29,1,31,1,33,1,35,1,37,1,39,1,41,1,43,1,45,1,47,1,49,1,51,1,53,1,55,1,57,1,59,1,61,1,63,1,65,1,67,1,69,1,71,1,73,1,75,1,77,1,79,1,81,1,83,1,85,1,87,1,89,1,91,1,93,1,95,1,97,1,99,1,101,1,103,1,105,1,107,1,109,1,111,1,113,1,115,1,117,1,119,1,121,1,123,1,125,1,127,1,129,1,131,1,133,1,135,1,137,1,139,1,141,1,143,1,145,1,147,1,149,1,151,1,153,1,155,1,157,1,159,1,161,1,163,1,165,1,167,1,169,1,171,1,173,1,175,1,177,1,179,1,181,1,183,1,185,1,187,1,189,1",
				"GNU.sparse.name":      "sparse-posix-0.1",
			},
			Format: FormatPAX,
		}, {
			Name:     "sparse-posix-1.0",
			Mode:     420,
			Uid:      1000,
			Gid:      1000,
			Size:     200,
			ModTime:  time.Unix(1392337404, 0),
			Typeflag: 0x30,
			Linkname: "",
			Uname:    "david",
			Gname:    "david",
			Devmajor: 0,
			Devminor: 0,
			PAXRecords: map[string]string{
				"GNU.sparse.major":    "1",
				"GNU.sparse.minor":    "0",
				"GNU.sparse.realsize": "200",
				"GNU.sparse.name":     "sparse-posix-1.0",
			},
			Format: FormatPAX,
		}, {
			Name:     "end",
			Mode:     420,
			Uid:      1000,
			Gid:      1000,
			Size:     4,
			ModTime:  time.Unix(1392398319, 0),
			Typeflag: 0x30,
			Linkname: "",
			Uname:    "david",
			Gname:    "david",
			Devmajor: 0,
			Devminor: 0,
			Format:   FormatGNU,
		}},
		chksums: []string{
			"5375e1d2",
			"5375e1d2",
			"5375e1d2",
			"5375e1d2",
			"8eb179ba",
		},
	}, {
		file: "testdata/star.tar",
		headers: []*Header{{
			Name:       "small.txt",
			Mode:       0640,
			Uid:        73025,
			Gid:        5000,
			Size:       5,
			ModTime:    time.Unix(1244592783, 0),
			Typeflag:   '0',
			Uname:      "dsymonds",
			Gname:      "eng",
			AccessTime: time.Unix(1244592783, 0),
			ChangeTime: time.Unix(1244592783, 0),
		}, {
			Name:       "small2.txt",
			Mode:       0640,
			Uid:        73025,
			Gid:        5000,
			Size:       11,
			ModTime:    time.Unix(1244592783, 0),
			Typeflag:   '0',
			Uname:      "dsymonds",
			Gname:      "eng",
			AccessTime: time.Unix(1244592783, 0),
			ChangeTime: time.Unix(1244592783, 0),
		}},
	}, {
		file: "testdata/v7.tar",
		headers: []*Header{{
			Name:     "small.txt",
			Mode:     0444,
			Uid:      73025,
			Gid:      5000,
			Size:     5,
			ModTime:  time.Unix(1244593104, 0),
			Typeflag: '0',
		}, {
			Name:     "small2.txt",
			Mode:     0444,
			Uid:      73025,
			Gid:      5000,
			Size:     11,
			ModTime:  time.Unix(1244593104, 0),
			Typeflag: '0',
		}},
	}, {
		file: "testdata/pax.tar",
		headers: []*Header{{
			Name:       "a/123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100",
			Mode:       0664,
			Uid:        1000,
			Gid:        1000,
			Uname:      "shane",
			Gname:      "shane",
			Size:       7,
			ModTime:    time.Unix(1350244992, 23960108),
			ChangeTime: time.Unix(1350244992, 23960108),
			AccessTime: time.Unix(1350244992, 23960108),
			Typeflag:   TypeReg,
			PAXRecords: map[string]string{
				"path":  "a/123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100",
				"mtime": "1350244992.023960108",
				"atime": "1350244992.023960108",
				"ctime": "1350244992.023960108",
			},
			Format: FormatPAX,
		}, {
			Name:       "a/b",
			Mode:       0777,
			Uid:        1000,
			Gid:        1000,
			Uname:      "shane",
			Gname:      "shane",
			Size:       0,
			ModTime:    time.Unix(1350266320, 910238425),
			ChangeTime: time.Unix(1350266320, 910238425),
			AccessTime: time.Unix(1350266320, 910238425),
			Typeflag:   TypeSymlink,
			Linkname:   "123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100",
			PAXRecords: map[string]string{
				"linkpath": "123456789101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899100",
				"mtime":    "1350266320.910238425",
				"atime":    "1350266320.910238425",
				"ctime":    "1350266320.910238425",
			},
			Format: FormatPAX,
		}},
	}, {
		file: "testdata/pax-bad-hdr-file.tar",
		err:  ErrHeader,
	}, {
		file: "testdata/pax-bad-hdr-large.tar.bz2",
		err:  ErrFieldTooLong,
	}, {
		file: "testdata/pax-bad-mtime-file.tar",
		err:  ErrHeader,
	}, {
		file: "testdata/pax-pos-size-file.tar",
		headers: []*Header{{
			Name:     "foo",
			Mode:     0640,
			Uid:      319973,
			Gid:      5000,
			Size:     999,
			ModTime:  time.Unix(1442282516, 0),
			Typeflag: '0',
			Uname:    "joetsai",
			Gname:    "eng",
			PAXRecords: map[string]string{
				"size": "000000000000000000000999",
			},
			Format: FormatPAX,
		}},
		chksums: []string{
			"5fd7e86a",
		},
	}, {
		file: "testdata/pax-records.tar",
		headers: []*Header{{
			Typeflag: TypeReg,
			Name:     "file",
			Uname:    strings.Repeat("long", 10),
			ModTime:  time.Unix(0, 0),
			PAXRecords: map[string]string{
				"GOLANG.pkg": "tar",
				"comment":    "Hello, 世界",
				"uname":      strings.Repeat("long", 10),
			},
			Format: FormatPAX,
		}},
	}, {
		file: "testdata/pax-global-records.tar",
		headers: []*Header{{
			Typeflag:   TypeXGlobalHeader,
			Name:       "global1",
			PAXRecords: map[string]string{"path": "global1", "mtime": "1500000000.0"},
			Format:     FormatPAX,
		}, {
			Typeflag: TypeReg,
			Name:     "file1",
			ModTime:  time.Unix(0, 0),
			Format:   FormatUSTAR,
		}, {
			Typeflag:   TypeReg,
			Name:       "file2",
			PAXRecords: map[string]string{"path": "file2"},
			ModTime:    time.Unix(0, 0),
			Format:     FormatPAX,
		}, {
			Typeflag:   TypeXGlobalHeader,
			Name:       "GlobalHead.0.0",
			PAXRecords: map[string]string{"path": ""},
			Format:     FormatPAX,
		}, {
			Typeflag: TypeReg,
			Name:     "file3",
			ModTime:  time.Unix(0, 0),
			Format:   FormatUSTAR,
		}, {
			Typeflag:   TypeReg,
			Name:       "file4",
			ModTime:    time.Unix(1400000000, 0),
			PAXRecords: map[string]string{"mtime": "1400000000"},
			Format:     FormatPAX,
		}},
	}, {
		file: "testdata/nil-uid.tar", // golang.org/issue/5290
		headers: []*Header{{
			Name:     "P1050238.JPG.log",
			Mode:     0664,
			Uid:      0,
			Gid:      0,
			Size:     14,
			ModTime:  time.Unix(1365454838, 0),
			Typeflag: TypeReg,
			Linkname: "",
			Uname:    "eyefi",
			Gname:    "eyefi",
			Devmajor: 0,
			Devminor: 0,
			Format:   FormatGNU,
		}},
	}, {
		file: "testdata/xattrs.tar",
		headers: []*Header{{
			Name:       "small.txt",
			Mode:       0644,
			Uid:        1000,
			Gid:        10,
			Size:       5,
			ModTime:    time.Unix(1386065770, 448252320),
			Typeflag:   '0',
			Uname:      "alex",
			Gname:      "wheel",
			AccessTime: time.Unix(1389782991, 419875220),
			ChangeTime: time.Unix(1389782956, 794414986),
			Xattrs: map[string]string{
				"user.key":  "value",
				"user.key2": "value2",
				// Interestingly, selinux encodes the terminating null inside the xattr
				"security.selinux": "unconfined_u:object_r:default_t:s0\x00",
			},
			PAXRecords: map[string]string{
				"mtime":                         "1386065770.44825232",
				"atime":                         "1389782991.41987522",
				"ctime":                         "1389782956.794414986",
				"SCHILY.xattr.user.key":         "value",
				"SCHILY.xattr.user.key2":        "value2",
				"SCHILY.xattr.security.selinux": "unconfined_u:object_r:default_t:s0\x00",
			},
			Format: FormatPAX,
		}, {
			Name:       "small2.txt",
			Mode:       0644,
			Uid:        1000,
			Gid:        10,
			Size:       11,
			ModTime:    time.Unix(1386065770, 449252304),
			Typeflag:   '0',
			Uname:      "alex",
			Gname:      "wheel",
			AccessTime: time.Unix(1389782991, 419875220),
			ChangeTime: time.Unix(1386065770, 449252304),
			Xattrs: map[string]string{
				"security.selinux": "unconfined_u:object_r:default_t:s0\x00",
			},
			PAXRecords: map[string]string{
				"mtime":                         "1386065770.449252304",
				"atime":                         "1389782991.41987522",
				"ctime":                         "1386065770.449252304",
				"SCHILY.xattr.security.selinux": "unconfined_u:object_r:default_t:s0\x00",
			},
			Format: FormatPAX,
		}},
	}, {
		// Matches the behavior of GNU, BSD, and STAR tar utilities.
		file: "testdata/gnu-multi-hdrs.tar",
		headers: []*Header{{
			Name:     "GNU2/GNU2/long-path-name",
			Linkname: "GNU4/GNU4/long-linkpath-name",
			ModTime:  time.Unix(0, 0),
			Typeflag: '2',
			Format:   FormatGNU,
		}},
	}, {
		// GNU tar file with atime and ctime fields set.
		// Created with the GNU tar v1.27.1.
		//	tar --incremental -S -cvf gnu-incremental.tar test2
		file: "testdata/gnu-incremental.tar",
		headers: []*Header{{
			Name:       "test2/",
			Mode:       16877,
			Uid:        1000,
			Gid:        1000,
			Size:       14,
			ModTime:    time.Unix(1441973427, 0),
			Typeflag:   'D',
			Uname:      "rawr",
			Gname:      "dsnet",
			AccessTime: time.Unix(1441974501, 0),
			ChangeTime: time.Unix(1441973436, 0),
			Format:     FormatGNU,
		}, {
			Name:       "test2/foo",
			Mode:       33188,
			Uid:        1000,
			Gid:        1000,
			Size:       64,
			ModTime:    time.Unix(1441973363, 0),
			Typeflag:   '0',
			Uname:      "rawr",
			Gname:      "dsnet",
			AccessTime: time.Unix(1441974501, 0),
			ChangeTime: time.Unix(1441973436, 0),
			Format:     FormatGNU,
		}, {
			Name:       "test2/sparse",
			Mode:       33188,
			Uid:        1000,
			Gid:        1000,
			Size:       536870912,
			ModTime:    time.Unix(1441973427, 0),
			Typeflag:   'S',
			Uname:      "rawr",
			Gname:      "dsnet",
			AccessTime: time.Unix(1441991948, 0),
			ChangeTime: time.Unix(1441973436, 0),
			Format:     FormatGNU,
		}},
	}, {
		// Matches the behavior of GNU and BSD tar utilities.
		file: "testdata/pax-multi-hdrs.tar",
		headers: []*Header{{
			Name:     "bar",
			Linkname: "PAX4/PAX4/long-linkpath-name",
			ModTime:  time.Unix(0, 0),
			Typeflag: '2',
			PAXRecords: map[string]string{
				"linkpath": "PAX4/PAX4/long-linkpath-name",
			},
			Format: FormatPAX,
		}},
	}, {
		// Both BSD and GNU tar truncate long names at first NUL even
		// if there is data following that NUL character.
		// This is reasonable as GNU long names are C-strings.
		file: "testdata/gnu-long-nul.tar",
		headers: []*Header{{
			Name:     "0123456789",
			Mode:     0644,
			Uid:      1000,
			Gid:      1000,
			ModTime:  time.Unix(1486082191, 0),
			Typeflag: '0',
			Uname:    "rawr",
			Gname:    "dsnet",
			Format:   FormatGNU,
		}},
	}, {
		// This archive was generated by Writer but is readable by both
		// GNU and BSD tar utilities.
		// The archive generated by GNU is nearly byte-for-byte identical
		// to the Go version except the Go version sets a negative Devminor
		// just to force the GNU format.
		file: "testdata/gnu-utf8.tar",
		headers: []*Header{{
			Name: "☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹☺☻☹",
			Mode: 0644,
			Uid:  1000, Gid: 1000,
			ModTime:  time.Unix(0, 0),
			Typeflag: '0',
			Uname:    "☺",
			Gname:    "⚹",
			Format:   FormatGNU,
		}},
	}, {
		// This archive was generated by Writer but is readable by both
		// GNU and BSD tar utilities.
		// The archive generated by GNU is nearly byte-for-byte identical
		// to the Go version except the Go version sets a negative Devminor
		// just to force the GNU format.
		file: "testdata/gnu-not-utf8.tar",
		headers: []*Header{{
			Name:     "hi\x80\x81\x82\x83bye",
			Mode:     0644,
			Uid:      1000,
			Gid:      1000,
			ModTime:  time.Unix(0, 0),
			Typeflag: '0',
			Uname:    "rawr",
			Gname:    "dsnet",
			Format:   FormatGNU,
		}},
	}, {
		// BSD tar v3.1.2 and GNU tar v1.27.1 both rejects PAX records
		// with NULs in the key.
		file: "testdata/pax-nul-xattrs.tar",
		err:  ErrHeader,
	}, {
		// BSD tar v3.1.2 rejects a PAX path with NUL in the value, while
		// GNU tar v1.27.1 simply truncates at first NUL.
		// We emulate the behavior of BSD since it is strange doing NUL
		// truncations since PAX records are length-prefix strings instead
		// of NUL-terminated C-strings.
		file: "testdata/pax-nul-path.tar",
		err:  ErrHeader,
	}, {
		file: "testdata/neg-size.tar",
		err:  ErrHeader,
	}, {
		file: "testdata/issue10968.tar",
		err:  ErrHeader,
	}, {
		file: "testdata/issue11169.tar",
		err:  ErrHeader,
	}, {
		file: "testdata/issue12435.tar",
		err:  ErrHeader,
	}, {
		// Ensure that we can read back the original Header as written with
		// a buggy pre-Go1.8 tar.Writer.
		file: "testdata/invalid-go17.tar",
		headers: []*Header{{
			Name:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/foo",
			Uid:      010000000,
			ModTime:  time.Unix(0, 0),
			Typeflag: '0',
		}},
	}, {
		// USTAR archive with a regular entry with non-zero device numbers.
		file: "testdata/ustar-file-devs.tar",
		headers: []*Header{{
			Name:     "file",
			Mode:     0644,
			Typeflag: '0',
			ModTime:  time.Unix(0, 0),
			Devmajor: 1,
			Devminor: 1,
			Format:   FormatUSTAR,
		}},
	}, {
		// Generated by Go, works on BSD tar v3.1.2 and GNU tar v.1.27.1.
		file: "testdata/gnu-nil-sparse-data.tar",
		headers: []*Header{{
			Name:     "sparse.db",
			Typeflag: TypeGNUSparse,
			Size:     1000,
			ModTime:  time.Unix(0, 0),
			Format:   FormatGNU,
		}},
	}, {
		// Generated by Go, works on BSD tar v3.1.2 and GNU tar v.1.27.1.
		file: "testdata/gnu-nil-sparse-hole.tar",
		headers: []*Header{{
			Name:     "sparse.db",
			Typeflag: TypeGNUSparse,
			Size:     1000,
			ModTime:  time.Unix(0, 0),
			Format:   FormatGNU,
		}},
	}, {
		// Generated by Go, works on BSD tar v3.1.2 and GNU tar v.1.27.1.
		file: "testdata/pax-nil-sparse-data.tar",
		headers: []*Header{{
			Name:     "sparse.db",
			Typeflag: TypeReg,
			Size:     1000,
			ModTime:  time.Unix(0, 0),
			PAXRecords: map[string]string{
				"size":                "1512",
				"GNU.sparse.major":    "1",
				"GNU.sparse.minor":    "0",
				"GNU.sparse.realsize": "1000",
				"GNU.sparse.name":     "sparse.db",
			},
			Format: FormatPAX,
		}},
	}, {
		// Generated by Go, works on BSD tar v3.1.2 and GNU tar v.1.27.1.
		file: "testdata/pax-nil-sparse-hole.tar",
		headers: []*Header{{
			Name:     "sparse.db",
			Typeflag: TypeReg,
			Size:     1000,
			ModTime:  time.Unix(0, 0),
			PAXRecords: map[string]string{
				"size":                "512",
				"GNU.sparse.major":    "1",
				"GNU.sparse.minor":    "0",
				"GNU.sparse.realsize": "1000",
				"GNU.sparse.name":     "sparse.db",
			},
			Format: FormatPAX,
		}},
	}, {
		file: "testdata/trailing-slash.tar",
		headers: []*Header{{
			Typeflag: TypeDir,
			Name:     strings.Repeat("123456789/", 30),
			ModTime:  time.Unix(0, 0),
			PAXRecords: map[string]string{
				"path": strings.Repeat("123456789/", 30),
			},
			Format: FormatPAX,
		}},
	}}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer f.Close()

			var fr io.Reader = f
			if strings.HasSuffix(v.file, ".bz2") {
				fr = bzip2.NewReader(fr)
			}

			// Capture all headers and checksums.
			var (
				tr      = NewReader(fr)
				hdrs    []*Header
				chksums []string
				rdbuf   = make([]byte, 8)
			)
			for {
				var hdr *Header
				hdr, err = tr.Next()
				if err != nil {
					if err == io.EOF {
						err = nil // Expected error
					}
					break
				}
				hdrs = append(hdrs, hdr)

				if v.chksums == nil {
					continue
				}
				h := crc32.NewIEEE()
				_, err = io.CopyBuffer(h, tr, rdbuf) // Effectively an incremental read
				if err != nil {
					break
				}
				chksums = append(chksums, fmt.Sprintf("%x", h.Sum(nil)))
			}

			for i, hdr := range hdrs {
				if i >= len(v.headers) {
					t.Fatalf("entry %d: unexpected header:\ngot %+v", i, *hdr)
				}
				if !reflect.DeepEqual(*hdr, *v.headers[i]) {
					t.Fatalf("entry %d: incorrect header:\ngot  %+v\nwant %+v", i, *hdr, *v.headers[i])
				}
			}
			if len(hdrs) != len(v.headers) {
				t.Fatalf("got %d headers, want %d headers", len(hdrs), len(v.headers))
			}

			for i, sum := range chksums {
				if i >= len(v.chksums) {
					t.Fatalf("entry %d: unexpected sum: got %s", i, sum)
				}
				if sum != v.chksums[i] {
					t.Fatalf("entry %d: incorrect checksum: got %s, want %s", i, sum, v.chksums[i])
				}
			}

			if err != v.err {
				t.Fatalf("unexpected error: got %v, want %v", err, v.err)
			}
			f.Close()
		})
	}
}

func TestPartialRead(t *testing.T) {
	type testCase struct {
		cnt    int    // Number of bytes to read
		output string // Expected value of string read
	}
	vectors := []struct {
		file  string
		cases []testCase
	}{{
		file: "testdata/gnu.tar",
		cases: []testCase{
			{4, "Kilt"},
			{6, "Google"},
		},
	}, {
		file: "testdata/sparse-formats.tar",
		cases: []testCase{
			{2, "\x00G"},
			{4, "\x00G\x00o"},
			{6, "\x00G\x00o\x00G"},
			{8, "\x00G\x00o\x00G\x00o"},
			{4, "end\n"},
		},
	}}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			defer f.Close()

			tr := NewReader(f)
			for i, tc := range v.cases {
				hdr, err := tr.Next()
				if err != nil || hdr == nil {
					t.Fatalf("entry %d, Next(): got %v, want %v", i, err, nil)
				}
				buf := make([]byte, tc.cnt)
				if _, err := io.ReadFull(tr, buf); err != nil {
					t.Fatalf("entry %d, ReadFull(): got %v, want %v", i, err, nil)
				}
				if string(buf) != tc.output {
					t.Fatalf("entry %d, ReadFull(): got %q, want %q", i, string(buf), tc.output)
				}
			}

			if _, err := tr.Next(); err != io.EOF {
				t.Fatalf("Next(): got %v, want EOF", err)
			}
		})
	}
}

func TestUninitializedRead(t *testing.T) {
	f, err := os.Open("testdata/gnu.tar")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	defer f.Close()

	tr := NewReader(f)
	_, err = tr.Read([]byte{})
	if err == nil || err != io.EOF {
		t.Errorf("Unexpected error: %v, wanted %v", err, io.EOF)
	}

}

type reader struct{ io.Reader }
type readSeeker struct{ io.ReadSeeker }
type readBadSeeker struct{ io.ReadSeeker }

func (rbs *readBadSeeker) Seek(int64, int) (int64, error) { return 0, fmt.Errorf("illegal seek") }

// TestReadTruncation test the ending condition on various truncated files and
// that truncated files are still detected even if the underlying io.Reader
// satisfies io.Seeker.
func TestReadTruncation(t *testing.T) {
	var ss []string
	for _, p := range []string{
		"testdata/gnu.tar",
		"testdata/ustar-file-reg.tar",
		"testdata/pax-path-hdr.tar",
		"testdata/sparse-formats.tar",
	} {
		buf, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ss = append(ss, string(buf))
	}

	data1, data2, pax, sparse := ss[0], ss[1], ss[2], ss[3]
	data2 += strings.Repeat("\x00", 10*512)
	trash := strings.Repeat("garbage ", 64) // Exactly 512 bytes

	vectors := []struct {
		input string // Input stream
		cnt   int    // Expected number of headers read
		err   error  // Expected error outcome
	}{
		{"", 0, io.EOF}, // Empty file is a "valid" tar file
		{data1[:511], 0, io.ErrUnexpectedEOF},
		{data1[:512], 1, io.ErrUnexpectedEOF},
		{data1[:1024], 1, io.EOF},
		{data1[:1536], 2, io.ErrUnexpectedEOF},
		{data1[:2048], 2, io.EOF},
		{data1, 2, io.EOF},
		{data1[:2048] + data2[:1536], 3, io.EOF},
		{data2[:511], 0, io.ErrUnexpectedEOF},
		{data2[:512], 1, io.ErrUnexpectedEOF},
		{data2[:1195], 1, io.ErrUnexpectedEOF},
		{data2[:1196], 1, io.EOF}, // Exact end of data and start of padding
		{data2[:1200], 1, io.EOF},
		{data2[:1535], 1, io.EOF},
		{data2[:1536], 1, io.EOF}, // Exact end of padding
		{data2[:1536] + trash[:1], 1, io.ErrUnexpectedEOF},
		{data2[:1536] + trash[:511], 1, io.ErrUnexpectedEOF},
		{data2[:1536] + trash, 1, ErrHeader},
		{data2[:2048], 1, io.EOF}, // Exactly 1 empty block
		{data2[:2048] + trash[:1], 1, io.ErrUnexpectedEOF},
		{data2[:2048] + trash[:511], 1, io.ErrUnexpectedEOF},
		{data2[:2048] + trash, 1, ErrHeader},
		{data2[:2560], 1, io.EOF}, // Exactly 2 empty blocks (normal end-of-stream)
		{data2[:2560] + trash[:1], 1, io.EOF},
		{data2[:2560] + trash[:511], 1, io.EOF},
		{data2[:2560] + trash, 1, io.EOF},
		{data2[:3072], 1, io.EOF},
		{pax, 0, io.EOF}, // PAX header without data is a "valid" tar file
		{pax + trash[:1], 0, io.ErrUnexpectedEOF},
		{pax + trash[:511], 0, io.ErrUnexpectedEOF},
		{sparse[:511], 0, io.ErrUnexpectedEOF},
		{sparse[:512], 0, io.ErrUnexpectedEOF},
		{sparse[:3584], 1, io.EOF},
		{sparse[:9200], 1, io.EOF}, // Terminate in padding of sparse header
		{sparse[:9216], 1, io.EOF},
		{sparse[:9728], 2, io.ErrUnexpectedEOF},
		{sparse[:10240], 2, io.EOF},
		{sparse[:11264], 2, io.ErrUnexpectedEOF},
		{sparse, 5, io.EOF},
		{sparse + trash, 5, io.EOF},
	}

	for i, v := range vectors {
		for j := 0; j < 6; j++ {
			var tr *Reader
			var s1, s2 string

			switch j {
			case 0:
				tr = NewReader(&reader{strings.NewReader(v.input)})
				s1, s2 = "io.Reader", "auto"
			case 1:
				tr = NewReader(&reader{strings.NewReader(v.input)})
				s1, s2 = "io.Reader", "manual"
			case 2:
				tr = NewReader(&readSeeker{strings.NewReader(v.input)})
				s1, s2 = "io.ReadSeeker", "auto"
			case 3:
				tr = NewReader(&readSeeker{strings.NewReader(v.input)})
				s1, s2 = "io.ReadSeeker", "manual"
			case 4:
				tr = NewReader(&readBadSeeker{strings.NewReader(v.input)})
				s1, s2 = "ReadBadSeeker", "auto"
			case 5:
				tr = NewReader(&readBadSeeker{strings.NewReader(v.input)})
				s1, s2 = "ReadBadSeeker", "manual"
			}

			var cnt int
			var err error
			for {
				if _, err = tr.Next(); err != nil {
					break
				}
				cnt++
				if s2 == "manual" {
					if _, err = tr.writeTo(io.Discard); err != nil {
						break
					}
				}
			}
			if err != v.err {
				t.Errorf("test %d, NewReader(%s) with %s discard: got %v, want %v",
					i, s1, s2, err, v.err)
			}
			if cnt != v.cnt {
				t.Errorf("test %d, NewReader(%s) with %s discard: got %d headers, want %d headers",
					i, s1, s2, cnt, v.cnt)
			}
		}
	}
}

// TestReadHeaderOnly tests that Reader does not attempt to read special
// header-only files.
func TestReadHeaderOnly(t *testing.T) {
	f, err := os.Open("testdata/hdr-only.tar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer f.Close()

	var hdrs []*Header
	tr := NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("Next(): got %v, want %v", err, nil)
			continue
		}
		hdrs = append(hdrs, hdr)

		// If a special flag, we should read nothing.
		cnt, _ := io.ReadFull(tr, []byte{0})
		if cnt > 0 && hdr.Typeflag != TypeReg {
			t.Errorf("ReadFull(...): got %d bytes, want 0 bytes", cnt)
		}
	}

	// File is crafted with 16 entries. The later 8 are identical to the first
	// 8 except that the size is set.
	if len(hdrs) != 16 {
		t.Fatalf("len(hdrs): got %d, want %d", len(hdrs), 16)
	}
	for i := 0; i < 8; i++ {
		hdr1, hdr2 := hdrs[i+0], hdrs[i+8]
		hdr1.Size, hdr2.Size = 0, 0
		if !reflect.DeepEqual(*hdr1, *hdr2) {
			t.Errorf("incorrect header:\ngot  %+v\nwant %+v", *hdr1, *hdr2)
		}
	}
}

func TestMergePAX(t *testing.T) {
	vectors := []struct {
		in   map[string]string
		want *Header
		ok   bool
	}{{
		in: map[string]string{
			"path":  "a/b/c",
			"uid":   "1000",
			"mtime": "1350244992.023960108",
		},
		want: &Header{
			Name:    "a/b/c",
			Uid:     1000,
			ModTime: time.Unix(1350244992, 23960108),
			PAXRecords: map[string]string{
				"path":  "a/b/c",
				"uid":   "1000",
				"mtime": "1350244992.023960108",
			},
		},
		ok: true,
	}, {
		in: map[string]string{
			"gid": "gtgergergersagersgers",
		},
		ok: false,
	}, {
		in: map[string]string{
			"missing":          "missing",
			"SCHILY.xattr.key": "value",
		},
		want: &Header{
			Xattrs: map[string]string{"key": "value"},
			PAXRecords: map[string]string{
				"missing":          "missing",
				"SCHILY.xattr.key": "value",
			},
		},
		ok: true,
	}}

	for i, v := range vectors {
		got := new(Header)
		err := mergePAX(got, v.in)
		if v.ok && !reflect.DeepEqual(*got, *v.want) {
			t.Errorf("test %d, mergePAX(...):\ngot  %+v\nwant %+v", i, *got, *v.want)
		}
		if ok := err == nil; ok != v.ok {
			t.Errorf("test %d, mergePAX(...): got %v, want %v", i, ok, v.ok)
		}
	}
}

func TestParsePAX(t *testing.T) {
	vectors := []struct {
		in   string
		want map[string]string
		ok   bool
	}{
		{"", nil, true},
		{"6 k=1\n", map[string]string{"k": "1"}, true},
		{"10 a=name\n", map[string]string{"a": "name"}, true},
		{"9 a=name\n", map[string]string{"a": "name"}, true},
		{"30 mtime=1350244992.023960108\n", map[string]string{"mtime": "1350244992.023960108"}, true},
		{"3 somelongkey=\n", nil, false},
		{"50 tooshort=\n", nil, false},
		{"13 key1=haha\n13 key2=nana\n13 key3=kaka\n",
			map[string]string{"key1": "haha", "key2": "nana", "key3": "kaka"}, true},
		{"13 key1=val1\n13 key2=val2\n8 key1=\n",
			map[string]string{"key1": "", "key2": "val2"}, true},
		{"22 GNU.sparse.size=10\n26 GNU.sparse.numblocks=2\n" +
			"23 GNU.sparse.offset=1\n25 GNU.sparse.numbytes=2\n" +
			"23 GNU.sparse.offset=3\n25 GNU.sparse.numbytes=4\n",
			map[string]string{paxGNUSparseSize: "10", paxGNUSparseNumBlocks: "2", paxGNUSparseMap: "1,2,3,4"}, true},
		{"22 GNU.sparse.size=10\n26 GNU.sparse.numblocks=1\n" +
			"25 GNU.sparse.numbytes=2\n23 GNU.sparse.offset=1\n",
			nil, false},
		{"22 GNU.sparse.size=10\n26 GNU.sparse.numblocks=1\n" +
			"25 GNU.sparse.offset=1,2\n25 GNU.sparse.numbytes=2\n",
			nil, false},
	}

	for i, v := range vectors {
		r := strings.NewReader(v.in)
		got, err := parsePAX(r)
		if !maps.Equal(got, v.want) && !(len(got) == 0 && len(v.want) == 0) {
			t.Errorf("test %d, parsePAX():\ngot  %v\nwant %v", i, got, v.want)
		}
		if ok := err == nil; ok != v.ok {
			t.Errorf("test %d, parsePAX(): got %v, want %v", i, ok, v.ok)
		}
	}
}

func TestReadOldGNUSparseMap(t *testing.T) {
	populateSparseMap := func(sa sparseArray, sps []string) []string {
		for i := 0; len(sps) > 0 && i < sa.maxEntries(); i++ {
			copy(sa.entry(i), sps[0])
			sps = sps[1:]
		}
		if len(sps) > 0 {
			copy(sa.isExtended(), "\x80")
		}
		return sps
	}

	makeInput := func(format Format, size string, sps ...string) (out []byte) {
		// Write the initial GNU header.
		var blk block
		gnu := blk.toGNU()
		sparse := gnu.sparse()
		copy(gnu.realSize(), size)
		sps = populateSparseMap(sparse, sps)
		if format != FormatUnknown {
			blk.setFormat(format)
		}
		out = append(out, blk[:]...)

		// Write extended sparse blocks.
		for len(sps) > 0 {
			var blk block
			sps = populateSparseMap(blk.toSparse(), sps)
			out = append(out, blk[:]...)
		}
		return out
	}

	makeSparseStrings := func(sp []sparseEntry) (out []string) {
		var f formatter
		for _, s := range sp {
			var b [24]byte
			f.formatNumeric(b[:12], s.Offset)
			f.formatNumeric(b[12:], s.Length)
			out = append(out, string(b[:]))
		}
		return out
	}

	vectors := []struct {
		input    []byte
		wantMap  sparseDatas
		wantSize int64
		wantErr  error
	}{{
		input:   makeInput(FormatUnknown, ""),
		wantErr: ErrHeader,
	}, {
		input:    makeInput(FormatGNU, "1234", "fewa"),
		wantSize: 01234,
		wantErr:  ErrHeader,
	}, {
		input:    makeInput(FormatGNU, "0031"),
		wantSize: 031,
	}, {
		input:   makeInput(FormatGNU, "80"),
		wantErr: ErrHeader,
	}, {
		input: makeInput(FormatGNU, "1234",
			makeSparseStrings(sparseDatas{{0, 0}, {1, 1}})...),
		wantMap:  sparseDatas{{0, 0}, {1, 1}},
		wantSize: 01234,
	}, {
		input: makeInput(FormatGNU, "1234",
			append(makeSparseStrings(sparseDatas{{0, 0}, {1, 1}}), []string{"", "blah"}...)...),
		wantMap:  sparseDatas{{0, 0}, {1, 1}},
		wantSize: 01234,
	}, {
		input: makeInput(FormatGNU, "3333",
			makeSparseStrings(sparseDatas{{0, 1}, {2, 1}, {4, 1}, {6, 1}})...),
		wantMap:  sparseDatas{{0, 1}, {2, 1}, {4, 1}, {6, 1}},
		wantSize: 03333,
	}, {
		input: makeInput(FormatGNU, "",
			append(append(
				makeSparseStrings(sparseDatas{{0, 1}, {2, 1}}),
				[]string{"", ""}...),
				makeSparseStrings(sparseDatas{{4, 1}, {6, 1}})...)...),
		wantMap: sparseDatas{{0, 1}, {2, 1}, {4, 1}, {6, 1}},
	}, {
		input: makeInput(FormatGNU, "",
			makeSparseStrings(sparseDatas{{0, 1}, {2, 1}, {4, 1}, {6, 1}, {8, 1}, {10, 1}})...)[:blockSize],
		wantErr: io.ErrUnexpectedEOF,
	}, {
		input: makeInput(FormatGNU, "",
			makeSparseStrings(sparseDatas{{0, 1}, {2, 1}, {4, 1}, {6, 1}, {8, 1}, {10, 1}})...)[:3*blockSize/2],
		wantErr: io.ErrUnexpectedEOF,
	}, {
		input: makeInput(FormatGNU, "",
			makeSparseStrings(sparseDatas{{0, 1}, {2, 1}, {4, 1}, {6, 1}, {8, 1}, {10, 1}})...),
		wantMap: sparseDatas{{0, 1}, {2, 1}, {4, 1}, {6, 1}, {8, 1}, {10, 1}},
	}, {
		input: makeInput(FormatGNU, "",
			makeSparseStrings(sparseDatas{{10 << 30, 512}, {20 << 30, 512}})...),
		wantMap: sparseDatas{{10 << 30, 512}, {20 << 30, 512}},
	}}

	for i, v := range vectors {
		var blk block
		var hdr Header
		v.input = v.input[copy(blk[:], v.input):]
		tr := Reader{r: bytes.NewReader(v.input)}
		got, err := tr.readOldGNUSparseMap(&hdr, &blk)
		if !slices.Equal(got, v.wantMap) {
			t.Errorf("test %d, readOldGNUSparseMap(): got %v, want %v", i, got, v.wantMap)
		}
		if err != v.wantErr {
			t.Errorf("test %d, readOldGNUSparseMap() = %v, want %v", i, err, v.wantErr)
		}
		if hdr.Size != v.wantSize {
			t.Errorf("test %d, Header.Size = %d, want %d", i, hdr.Size, v.wantSize)
		}
	}
}

func TestReadGNUSparsePAXHeaders(t *testing.T) {
	padInput := func(s string) string {
		return s + string(zeroBlock[:blockPadding(int64(len(s)))])
	}

	vectors := []struct {
		inputData string
		inputHdrs 
"""




```