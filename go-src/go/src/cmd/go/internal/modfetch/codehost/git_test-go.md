Response: The user wants to understand the functionality of the provided Go code snippet, which is a test file for Git-related operations within the `codehost` package of the Go toolchain.

Here's a breakdown of the thinking process to arrive at the answer:

1. **Identify the Core Purpose:** The file name `git_test.go` and the import of `cmd/go/internal/modfetch/codehost` strongly suggest this file contains tests for Git repository interactions.

2. **Analyze Imports:** The imported packages provide clues about the functionalities being tested:
    * `archive/zip`:  Indicates testing of ZIP archive handling.
    * `bytes`: Likely used for in-memory byte buffer manipulation.
    * `cmd/go/internal/cfg`: Suggests interaction with Go's configuration.
    * `cmd/go/internal/vcweb/vcstest`:  This is a test server for version control systems, crucial for setting up test repositories.
    * `context`: Standard Go context for managing operation lifecycles.
    * `flag`: For parsing command-line flags (though mainly in `TestMain`).
    * `internal/testenv`: Go's internal testing utilities.
    * `io`, `io/fs`: Basic input/output operations and file system interfaces.
    * `log`: For logging test outputs.
    * `os`, `path`, `path/filepath`: Operating system and path manipulation.
    * `reflect`: For deep comparison of data structures in tests.
    * `runtime`: To check the operating system for conditional test execution.
    * `strings`: String manipulation.
    * `sync`: For synchronization primitives (like `sync.Once`).
    * `testing`: The core Go testing package.
    * `time`: For time-related assertions in tests.

3. **Examine `TestMain`:** This function is the entry point for the tests. Its primary functions are:
    * Parsing flags (although minimal in this case).
    * Setting up a test server using `vcstest.NewServer()`. This server likely hosts mock Git repositories.
    * Creating a temporary directory for test files.
    * Setting `cfg.GOMODCACHE` to a temporary location to isolate test runs.

4. **Identify Helper Functions:** Functions like `testContext`, `newTestWriter`, and `testRepo` are helpers to streamline test setup. `testRepo` is particularly important as it creates a `Repo` interface instance for different VCS types (currently Git and Mercurial).

5. **Analyze Test Functions:**  Each `Test...` function focuses on testing a specific aspect of the `codehost` package's interaction with Git:
    * `TestTags`: Fetches and verifies tags from a Git repository.
    * `TestLatest`: Retrieves and validates the latest revision information.
    * `TestReadFile`: Reads and checks the content of a specific file at a given revision.
    * `TestReadZip`: Downloads a ZIP archive of a repository at a specific revision and verifies its contents.
    * `TestStat`: Retrieves and verifies revision information (like commit hash, time, tags) for a given revision identifier.

6. **Infer Functionality based on Tests:** By examining the assertions within each test function, it's possible to deduce the core functionality being tested. For example, `TestTags` calls a `Tags` method on a `Repo` instance, suggesting the `Repo` interface (and its Git implementation) has a method to list tags.

7. **Code Examples (Based on Inference):** Based on the test functions, one can infer the structure and usage of the underlying `codehost` package. The examples are constructed by imagining how the `Repo` interface and its methods might be used in a real-world scenario.

8. **Command-Line Argument Analysis:**  `TestMain` uses `flag.Parse()`, but the specific flags being parsed are not explicitly defined within this snippet. The explanation focuses on the general purpose of `flag.Parse()` in the context of Go tests.

9. **Common Mistakes:**  The analysis focuses on potential pitfalls related to relying on external state (like global variables for repository paths) and the importance of cleaning up resources. The `localGitURLOnce` pattern is highlighted as a potential area for race conditions if not handled carefully.

10. **Refinement and Organization:** The final step involves organizing the findings into a clear and structured answer, addressing each part of the user's request (functionality, code examples, command-line arguments, and common mistakes). Using code blocks and clear explanations enhances readability.
这段代码是 Go 语言标准库中 `cmd/go` 工具的一部分，具体来说，它位于 `internal/modfetch/codehost` 包下，并且是针对 **Git 版本控制系统** 的集成测试文件 `git_test.go` 的一部分。

它的主要功能是 **测试 `codehost` 包中与 Git 仓库交互的功能**。这个包的主要职责是提供一个统一的接口来处理各种代码托管服务，包括 Git、Mercurial 等。这个 `git_test.go` 文件专注于测试与 Git 仓库进行交互的特定实现。

以下是它的一些具体功能点：

1. **初始化测试环境 (`TestMain` 函数):**
   - 使用 `vcstest.NewServer()` 创建一个临时的、用于测试的版本控制服务器。这个服务器模拟了远程 Git 仓库，允许测试在隔离的环境中进行。
   - 设置全局变量 `gitrepo1`，使其指向测试服务器上的一个 Git 仓库。
   - 创建一个临时的本地目录 `localGitRepo`，用于模拟本地 Git 仓库。
   - 使用 `git clone --mirror` 命令将远程仓库 `gitrepo1` 克隆到本地 `localGitRepo`，并配置允许 `git archive` 操作。这模拟了从本地文件系统访问 Git 仓库的情况。
   - 将 Go 模块缓存 `GOMODCACHE` 重定向到一个新的临时目录，以避免测试之间的相互影响。

2. **辅助测试函数:**
   - `testContext(t testing.TB)`: 创建一个带有测试输出写入器的 `context.Context`，用于在测试中传递上下文信息。
   - `newTestWriter(t testing.TB)`: 创建一个自定义的 `io.Writer`，它会将写入的数据缓冲，并在遇到换行符时一次性输出到测试日志中。
   - `testRepo(ctx context.Context, t *testing.T, remote string)`:  根据提供的 `remote` 字符串（可以是一个预定义的变量，如 `gitrepo1` 或 `"localGitRepo"`），创建一个 `Repo` 接口的实例。这个接口代表一个代码仓库。对于 Git 仓库，它会返回一个 `gitRepo` 类型的实例。这个函数会根据 `remote` 的值来决定是连接到远程测试服务器上的仓库还是本地的仓库。

3. **测试获取标签 (`TestTags` 函数):**
   - 测试 `Repo` 接口的 `Tags` 方法，该方法用于获取仓库的标签列表。
   - 它定义了一系列测试用例，每个用例指定一个仓库 (`repo`) 和一个标签前缀 (`prefix`)，以及期望返回的标签列表 (`tags`)。
   - 对于每个测试用例，它会调用 `testRepo` 获取 `Repo` 实例，然后调用 `Tags` 方法，并使用 `reflect.DeepEqual` 比较实际返回的标签列表和期望的列表。
   - 特别地，它会针对 `gitrepo1` 和其本地克隆 `localGitRepo` 进行测试，还会针对另一种版本控制系统 `hgrepo1` 进行测试，以验证通用的 VCS 逻辑。

4. **测试获取最新版本信息 (`TestLatest` 函数):**
   - 测试 `Repo` 接口的 `Latest` 方法，该方法用于获取仓库的最新版本信息（例如，最新的提交哈希、时间、标签）。
   - 它定义了一系列测试用例，每个用例指定一个仓库 (`repo`) 和期望的 `RevInfo` 结构体，该结构体包含了版本信息。
   - 同样，它会针对不同的仓库进行测试，并使用 `reflect.DeepEqual` 比较实际返回的 `RevInfo` 和期望的 `RevInfo`。

5. **测试读取文件内容 (`TestReadFile` 函数):**
   - 测试 `Repo` 接口的 `ReadFile` 方法，该方法用于读取仓库中指定版本（`rev`）的指定文件（`file`）的内容。
   - 测试用例涵盖了读取存在的和不存在的文件，以及指定不同版本的情况。
   - 它会检查是否返回了预期的内容或者预期的错误。

6. **测试读取 ZIP 压缩包 (`TestReadZip` 函数):**
   - 测试 `Repo` 接口的 `ReadZip` 方法，该方法用于获取仓库指定版本（`rev`）下指定子目录（`subdir`）的 ZIP 压缩包。
   - 测试用例验证了能够正确下载并解压 ZIP 文件，并检查了 ZIP 文件中包含的文件名和大小是否符合预期。
   - 它还测试了指定不存在的修订版本的情况，期望返回特定的错误。

7. **测试获取版本信息 (`TestStat` 函数):**
   - 测试 `Repo` 接口的 `Stat` 方法，该方法用于获取仓库中指定版本（`rev`）的详细信息，例如提交哈希、提交时间、关联的标签等。
   - 测试用例覆盖了不同的 `rev` 值，包括分支名、标签名、提交哈希的前缀等。
   - 它会比较实际返回的 `RevInfo` 结构体和期望的结构体。

**可以推理出它是什么 Go 语言功能的实现:**

根据这些测试，我们可以推断出 `internal/modfetch/codehost` 包旨在实现一个通用的代码仓库访问接口，允许 Go 工具链以统一的方式与不同的版本控制系统（目前主要是 Git 和 Mercurial）进行交互。

**Go 代码举例说明:**

假设我们有一个实现了 `Repo` 接口的 `gitRepo` 结构体，并且该结构体实现了 `Tags` 方法：

```go
package codehost

import "context"

type Tag struct {
	Name string
	Hash string
}

type TagsResult struct {
	List []Tag
}

// Repo 是一个表示代码仓库的接口
type Repo interface {
	Tags(ctx context.Context, prefix string) (*TagsResult, error)
	Latest(ctx context.Context) (*RevInfo, error)
	ReadFile(ctx context.Context, rev, file string, maxSize int64) ([]byte, error)
	ReadZip(ctx context.Context, rev, subdir string, maxSize int64) (io.ReadCloser, error)
	Stat(ctx context.Context, rev string) (*RevInfo, error)
}

// gitRepo 是 Repo 接口的 Git 实现
type gitRepo struct {
	dir string
	url string
}

func (r *gitRepo) Tags(ctx context.Context, prefix string) (*TagsResult, error) {
	// 假设这里会调用 Git 命令来获取标签
	// 例如: git tag --list "prefix*"
	// ... (Git 命令执行逻辑) ...
	tags := []Tag{
		{"v1.0.0", "abcdef123456"},
		{"v1.0.1", "ghijkl789012"},
	}
	return &TagsResult{List: tags}, nil
}

// ... 其他 Repo 接口方法的实现 ...
```

**假设的输入与输出 (针对 `TestTags`):**

**假设输入:**
- `tt.repo`: `gitrepo1` (指向测试服务器上的 Git 仓库)
- `tt.prefix`: `"v1"`

**假设输出:**
```
&TagsResult{
	List: []Tag{
		{Name: "v1.2.3", Hash: "ede458df7cd0fdca520df19a33158086a8a68e81"},
		{Name: "v1.2.4-annotated", Hash: "ede458df7cd0fdca520df19a33158086a8a68e81"},
	},
}
```

**命令行参数的具体处理:**

在 `TestMain` 函数中，`flag.Parse()` 被调用。这会解析 Go 测试框架提供的命令行参数。虽然这段代码本身没有定义任何特定的 flag，但 `go test` 命令本身会接收一些标准参数，例如：

- `-v`:  启用详细输出，显示所有测试函数的运行情况。
- `-run <regexp>`:  只运行名称匹配指定正则表达式的测试函数。
- `-bench <regexp>`: 只运行名称匹配指定正则表达式的性能测试函数。
- `-count n`:  多次运行每个测试。
- `-timeout d`:  设置测试的超时时间。

`cfg.BuildX = testing.Verbose()` 这行代码将 `-v` flag 的值传递给了 `cfg.BuildX`，这个变量可能用于控制构建过程中的详细输出。

**使用者易犯错的点:**

1. **依赖全局状态:** 代码中使用了全局变量 (`gitrepo1`, `hgrepo1`, `localGitRepo`) 来存储仓库路径。如果在多个测试文件中都使用这些全局变量，并且测试没有正确地清理或隔离环境，可能会导致测试之间的相互干扰，使得某些测试在特定的执行顺序下才会失败。例如，一个测试修改了本地仓库的状态，而另一个依赖于原始状态的测试可能会失败。

2. **未清理临时资源:** `TestMain` 函数使用了 `os.MkdirTemp` 创建临时目录，并使用了 `defer` 语句来清理这些目录。但是，如果测试代码中有提前退出的情况（例如，使用了 `t.Fatal`），`defer` 语句可能不会被执行，导致临时资源泄露。虽然在这个特定的文件中处理得还不错，但在更复杂的测试场景中需要注意。

3. **对外部命令的依赖:** 测试中使用了 `git` 命令。如果执行测试的环境中没有安装 `git`，或者 `git` 的版本不符合预期，测试将会失败。虽然代码中使用了 `testenv.MustHaveExecPath(t, "git")` 来检查 `git` 是否存在，但仍然需要确保测试环境的配置。

4. **测试覆盖率不足:**  虽然这个文件测试了与 Git 仓库交互的一些基本功能，但可能没有覆盖所有可能的场景和错误情况。例如，对于网络错误、权限问题、Git 仓库损坏等情况的测试可能需要额外的考虑。

总而言之，这段代码通过使用模拟的 Git 服务器和本地仓库，对 `codehost` 包中与 Git 仓库交互的功能进行了全面的单元测试。它涵盖了获取标签、最新版本信息、读取文件和 ZIP 文件、以及获取版本状态等核心操作。

Prompt: 
```
这是路径为go/src/cmd/go/internal/modfetch/codehost/git_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package codehost

import (
	"archive/zip"
	"bytes"
	"cmd/go/internal/cfg"
	"cmd/go/internal/vcweb/vcstest"
	"context"
	"flag"
	"internal/testenv"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if err := testMain(m); err != nil {
		log.Fatal(err)
	}
}

var gitrepo1, hgrepo1, vgotest1 string

var altRepos = func() []string {
	return []string{
		"localGitRepo",
		hgrepo1,
	}
}

// TODO: Convert gitrepo1 to svn, bzr, fossil and add tests.
// For now, at least the hgrepo1 tests check the general vcs.go logic.

// localGitRepo is like gitrepo1 but allows archive access
// (although that doesn't really matter after CL 120041),
// and has a file:// URL instead of http:// or https://
// (which might still matter).
var localGitRepo string

// localGitURL initializes the repo in localGitRepo and returns its URL.
func localGitURL(t testing.TB) string {
	testenv.MustHaveExecPath(t, "git")
	if runtime.GOOS == "android" && strings.HasSuffix(testenv.Builder(), "-corellium") {
		testenv.SkipFlaky(t, 59940)
	}

	localGitURLOnce.Do(func() {
		// Clone gitrepo1 into a local directory.
		// If we use a file:// URL to access the local directory,
		// then git starts up all the usual protocol machinery,
		// which will let us test remote git archive invocations.
		_, localGitURLErr = Run(context.Background(), "", "git", "clone", "--mirror", gitrepo1, localGitRepo)
		if localGitURLErr != nil {
			return
		}
		repo := gitRepo{dir: localGitRepo}
		_, localGitURLErr = repo.runGit(context.Background(), "git", "config", "daemon.uploadarch", "true")
	})

	if localGitURLErr != nil {
		t.Fatal(localGitURLErr)
	}
	// Convert absolute path to file URL. LocalGitRepo will not accept
	// Windows absolute paths because they look like a host:path remote.
	// TODO(golang.org/issue/32456): use url.FromFilePath when implemented.
	if strings.HasPrefix(localGitRepo, "/") {
		return "file://" + localGitRepo
	} else {
		return "file:///" + filepath.ToSlash(localGitRepo)
	}
}

var (
	localGitURLOnce sync.Once
	localGitURLErr  error
)

func testMain(m *testing.M) (err error) {
	cfg.BuildX = testing.Verbose()

	srv, err := vcstest.NewServer()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := srv.Close(); err == nil {
			err = closeErr
		}
	}()

	gitrepo1 = srv.HTTP.URL + "/git/gitrepo1"
	hgrepo1 = srv.HTTP.URL + "/hg/hgrepo1"
	vgotest1 = srv.HTTP.URL + "/git/vgotest1"

	dir, err := os.MkdirTemp("", "gitrepo-test-")
	if err != nil {
		return err
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); err == nil {
			err = rmErr
		}
	}()

	localGitRepo = filepath.Join(dir, "gitrepo2")

	// Redirect the module cache to a fresh directory to avoid crosstalk, and make
	// it read/write so that the test can still clean it up easily when done.
	cfg.GOMODCACHE = filepath.Join(dir, "modcache")
	cfg.ModCacheRW = true

	m.Run()
	return nil
}

func testContext(t testing.TB) context.Context {
	w := newTestWriter(t)
	return cfg.WithBuildXWriter(context.Background(), w)
}

// A testWriter is an io.Writer that writes to a test's log.
//
// The writer batches written data until the last byte of a write is a newline
// character, then flushes the batched data as a single call to Logf.
// Any remaining unflushed data is logged during Cleanup.
type testWriter struct {
	t testing.TB

	mu  sync.Mutex
	buf bytes.Buffer
}

func newTestWriter(t testing.TB) *testWriter {
	w := &testWriter{t: t}

	t.Cleanup(func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if b := w.buf.Bytes(); len(b) > 0 {
			w.t.Logf("%s", b)
			w.buf.Reset()
		}
	})

	return w
}

func (w *testWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	if b := w.buf.Bytes(); len(b) > 0 && b[len(b)-1] == '\n' {
		w.t.Logf("%s", b)
		w.buf.Reset()
	}
	return n, err
}

func testRepo(ctx context.Context, t *testing.T, remote string) (Repo, error) {
	if remote == "localGitRepo" {
		return NewRepo(ctx, "git", localGitURL(t), false)
	}
	vcsName := "git"
	for _, k := range []string{"hg"} {
		if strings.Contains(remote, "/"+k+"/") {
			vcsName = k
		}
	}
	if testing.Short() && vcsName == "hg" {
		t.Skipf("skipping hg test in short mode: hg is slow")
	}
	testenv.MustHaveExecPath(t, vcsName)
	if runtime.GOOS == "android" && strings.HasSuffix(testenv.Builder(), "-corellium") {
		testenv.SkipFlaky(t, 59940)
	}
	return NewRepo(ctx, vcsName, remote, false)
}

func TestTags(t *testing.T) {
	t.Parallel()

	type tagsTest struct {
		repo   string
		prefix string
		tags   []Tag
	}

	runTest := func(tt tagsTest) func(*testing.T) {
		return func(t *testing.T) {
			t.Parallel()
			ctx := testContext(t)

			r, err := testRepo(ctx, t, tt.repo)
			if err != nil {
				t.Fatal(err)
			}
			tags, err := r.Tags(ctx, tt.prefix)
			if err != nil {
				t.Fatal(err)
			}
			if tags == nil || !reflect.DeepEqual(tags.List, tt.tags) {
				t.Errorf("Tags(%q): incorrect tags\nhave %v\nwant %v", tt.prefix, tags, tt.tags)
			}
		}
	}

	for _, tt := range []tagsTest{
		{gitrepo1, "xxx", []Tag{}},
		{gitrepo1, "", []Tag{
			{"v1.2.3", "ede458df7cd0fdca520df19a33158086a8a68e81"},
			{"v1.2.4-annotated", "ede458df7cd0fdca520df19a33158086a8a68e81"},
			{"v2.0.1", "76a00fb249b7f93091bc2c89a789dab1fc1bc26f"},
			{"v2.0.2", "9d02800338b8a55be062c838d1f02e0c5780b9eb"},
			{"v2.3", "76a00fb249b7f93091bc2c89a789dab1fc1bc26f"},
		}},
		{gitrepo1, "v", []Tag{
			{"v1.2.3", "ede458df7cd0fdca520df19a33158086a8a68e81"},
			{"v1.2.4-annotated", "ede458df7cd0fdca520df19a33158086a8a68e81"},
			{"v2.0.1", "76a00fb249b7f93091bc2c89a789dab1fc1bc26f"},
			{"v2.0.2", "9d02800338b8a55be062c838d1f02e0c5780b9eb"},
			{"v2.3", "76a00fb249b7f93091bc2c89a789dab1fc1bc26f"},
		}},
		{gitrepo1, "v1", []Tag{
			{"v1.2.3", "ede458df7cd0fdca520df19a33158086a8a68e81"},
			{"v1.2.4-annotated", "ede458df7cd0fdca520df19a33158086a8a68e81"},
		}},
		{gitrepo1, "2", []Tag{}},
	} {
		t.Run(path.Base(tt.repo)+"/"+tt.prefix, runTest(tt))
		if tt.repo == gitrepo1 {
			// Clear hashes.
			clearTags := []Tag{}
			for _, tag := range tt.tags {
				clearTags = append(clearTags, Tag{tag.Name, ""})
			}
			tags := tt.tags
			for _, tt.repo = range altRepos() {
				if strings.Contains(tt.repo, "Git") {
					tt.tags = tags
				} else {
					tt.tags = clearTags
				}
				t.Run(path.Base(tt.repo)+"/"+tt.prefix, runTest(tt))
			}
		}
	}
}

func TestLatest(t *testing.T) {
	t.Parallel()

	type latestTest struct {
		repo string
		info *RevInfo
	}
	runTest := func(tt latestTest) func(*testing.T) {
		return func(t *testing.T) {
			t.Parallel()
			ctx := testContext(t)

			r, err := testRepo(ctx, t, tt.repo)
			if err != nil {
				t.Fatal(err)
			}
			info, err := r.Latest(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(info, tt.info) {
				t.Errorf("Latest: incorrect info\nhave %+v (origin %+v)\nwant %+v (origin %+v)", info, info.Origin, tt.info, tt.info.Origin)
			}
		}
	}

	for _, tt := range []latestTest{
		{
			gitrepo1,
			&RevInfo{
				Origin: &Origin{
					VCS:  "git",
					URL:  gitrepo1,
					Ref:  "HEAD",
					Hash: "ede458df7cd0fdca520df19a33158086a8a68e81",
				},
				Name:    "ede458df7cd0fdca520df19a33158086a8a68e81",
				Short:   "ede458df7cd0",
				Version: "ede458df7cd0fdca520df19a33158086a8a68e81",
				Time:    time.Date(2018, 4, 17, 19, 43, 22, 0, time.UTC),
				Tags:    []string{"v1.2.3", "v1.2.4-annotated"},
			},
		},
		{
			hgrepo1,
			&RevInfo{
				Origin: &Origin{
					VCS:  "hg",
					URL:  hgrepo1,
					Hash: "18518c07eb8ed5c80221e997e518cccaa8c0c287",
				},
				Name:    "18518c07eb8ed5c80221e997e518cccaa8c0c287",
				Short:   "18518c07eb8e",
				Version: "18518c07eb8ed5c80221e997e518cccaa8c0c287",
				Time:    time.Date(2018, 6, 27, 16, 16, 30, 0, time.UTC),
			},
		},
	} {
		t.Run(path.Base(tt.repo), runTest(tt))
		if tt.repo == gitrepo1 {
			tt.repo = "localGitRepo"
			info := *tt.info
			tt.info = &info
			o := *info.Origin
			info.Origin = &o
			o.URL = localGitURL(t)
			t.Run(path.Base(tt.repo), runTest(tt))
		}
	}
}

func TestReadFile(t *testing.T) {
	t.Parallel()

	type readFileTest struct {
		repo string
		rev  string
		file string
		err  string
		data string
	}
	runTest := func(tt readFileTest) func(*testing.T) {
		return func(t *testing.T) {
			t.Parallel()
			ctx := testContext(t)

			r, err := testRepo(ctx, t, tt.repo)
			if err != nil {
				t.Fatal(err)
			}
			data, err := r.ReadFile(ctx, tt.rev, tt.file, 100)
			if err != nil {
				if tt.err == "" {
					t.Fatalf("ReadFile: unexpected error %v", err)
				}
				if !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("ReadFile: wrong error %q, want %q", err, tt.err)
				}
				if len(data) != 0 {
					t.Errorf("ReadFile: non-empty data %q with error %v", data, err)
				}
				return
			}
			if tt.err != "" {
				t.Fatalf("ReadFile: no error, wanted %v", tt.err)
			}
			if string(data) != tt.data {
				t.Errorf("ReadFile: incorrect data\nhave %q\nwant %q", data, tt.data)
			}
		}
	}

	for _, tt := range []readFileTest{
		{
			repo: gitrepo1,
			rev:  "latest",
			file: "README",
			data: "",
		},
		{
			repo: gitrepo1,
			rev:  "v2",
			file: "another.txt",
			data: "another\n",
		},
		{
			repo: gitrepo1,
			rev:  "v2.3.4",
			file: "another.txt",
			err:  fs.ErrNotExist.Error(),
		},
	} {
		t.Run(path.Base(tt.repo)+"/"+tt.rev+"/"+tt.file, runTest(tt))
		if tt.repo == gitrepo1 {
			for _, tt.repo = range altRepos() {
				t.Run(path.Base(tt.repo)+"/"+tt.rev+"/"+tt.file, runTest(tt))
			}
		}
	}
}

type zipFile struct {
	name string
	size int64
}

func TestReadZip(t *testing.T) {
	t.Parallel()

	type readZipTest struct {
		repo   string
		rev    string
		subdir string
		err    string
		files  map[string]uint64
	}
	runTest := func(tt readZipTest) func(*testing.T) {
		return func(t *testing.T) {
			t.Parallel()
			ctx := testContext(t)

			r, err := testRepo(ctx, t, tt.repo)
			if err != nil {
				t.Fatal(err)
			}
			rc, err := r.ReadZip(ctx, tt.rev, tt.subdir, 100000)
			if err != nil {
				if tt.err == "" {
					t.Fatalf("ReadZip: unexpected error %v", err)
				}
				if !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("ReadZip: wrong error %q, want %q", err, tt.err)
				}
				if rc != nil {
					t.Errorf("ReadZip: non-nil io.ReadCloser with error %v", err)
				}
				return
			}
			defer rc.Close()
			if tt.err != "" {
				t.Fatalf("ReadZip: no error, wanted %v", tt.err)
			}
			zipdata, err := io.ReadAll(rc)
			if err != nil {
				t.Fatal(err)
			}
			z, err := zip.NewReader(bytes.NewReader(zipdata), int64(len(zipdata)))
			if err != nil {
				t.Fatalf("ReadZip: cannot read zip file: %v", err)
			}
			have := make(map[string]bool)
			for _, f := range z.File {
				size, ok := tt.files[f.Name]
				if !ok {
					t.Errorf("ReadZip: unexpected file %s", f.Name)
					continue
				}
				have[f.Name] = true
				if size != ^uint64(0) && f.UncompressedSize64 != size {
					t.Errorf("ReadZip: file %s has unexpected size %d != %d", f.Name, f.UncompressedSize64, size)
				}
			}
			for name := range tt.files {
				if !have[name] {
					t.Errorf("ReadZip: missing file %s", name)
				}
			}
		}
	}

	for _, tt := range []readZipTest{
		{
			repo:   gitrepo1,
			rev:    "v2.3.4",
			subdir: "",
			files: map[string]uint64{
				"prefix/":       0,
				"prefix/README": 0,
				"prefix/v2":     3,
			},
		},
		{
			repo:   hgrepo1,
			rev:    "v2.3.4",
			subdir: "",
			files: map[string]uint64{
				"prefix/.hg_archival.txt": ^uint64(0),
				"prefix/README":           0,
				"prefix/v2":               3,
			},
		},

		{
			repo:   gitrepo1,
			rev:    "v2",
			subdir: "",
			files: map[string]uint64{
				"prefix/":            0,
				"prefix/README":      0,
				"prefix/v2":          3,
				"prefix/another.txt": 8,
				"prefix/foo.txt":     13,
			},
		},
		{
			repo:   hgrepo1,
			rev:    "v2",
			subdir: "",
			files: map[string]uint64{
				"prefix/.hg_archival.txt": ^uint64(0),
				"prefix/README":           0,
				"prefix/v2":               3,
				"prefix/another.txt":      8,
				"prefix/foo.txt":          13,
			},
		},

		{
			repo:   gitrepo1,
			rev:    "v3",
			subdir: "",
			files: map[string]uint64{
				"prefix/":                    0,
				"prefix/v3/":                 0,
				"prefix/v3/sub/":             0,
				"prefix/v3/sub/dir/":         0,
				"prefix/v3/sub/dir/file.txt": 16,
				"prefix/README":              0,
			},
		},
		{
			repo:   hgrepo1,
			rev:    "v3",
			subdir: "",
			files: map[string]uint64{
				"prefix/.hg_archival.txt":    ^uint64(0),
				"prefix/.hgtags":             405,
				"prefix/v3/sub/dir/file.txt": 16,
				"prefix/README":              0,
			},
		},

		{
			repo:   gitrepo1,
			rev:    "v3",
			subdir: "v3/sub/dir",
			files: map[string]uint64{
				"prefix/":                    0,
				"prefix/v3/":                 0,
				"prefix/v3/sub/":             0,
				"prefix/v3/sub/dir/":         0,
				"prefix/v3/sub/dir/file.txt": 16,
			},
		},
		{
			repo:   hgrepo1,
			rev:    "v3",
			subdir: "v3/sub/dir",
			files: map[string]uint64{
				"prefix/v3/sub/dir/file.txt": 16,
			},
		},

		{
			repo:   gitrepo1,
			rev:    "v3",
			subdir: "v3/sub",
			files: map[string]uint64{
				"prefix/":                    0,
				"prefix/v3/":                 0,
				"prefix/v3/sub/":             0,
				"prefix/v3/sub/dir/":         0,
				"prefix/v3/sub/dir/file.txt": 16,
			},
		},
		{
			repo:   hgrepo1,
			rev:    "v3",
			subdir: "v3/sub",
			files: map[string]uint64{
				"prefix/v3/sub/dir/file.txt": 16,
			},
		},

		{
			repo:   gitrepo1,
			rev:    "aaaaaaaaab",
			subdir: "",
			err:    "unknown revision",
		},
		{
			repo:   hgrepo1,
			rev:    "aaaaaaaaab",
			subdir: "",
			err:    "unknown revision",
		},

		{
			repo:   vgotest1,
			rev:    "submod/v1.0.4",
			subdir: "submod",
			files: map[string]uint64{
				"prefix/":                0,
				"prefix/submod/":         0,
				"prefix/submod/go.mod":   53,
				"prefix/submod/pkg/":     0,
				"prefix/submod/pkg/p.go": 31,
			},
		},
	} {
		t.Run(path.Base(tt.repo)+"/"+tt.rev+"/"+tt.subdir, runTest(tt))
		if tt.repo == gitrepo1 {
			tt.repo = "localGitRepo"
			t.Run(path.Base(tt.repo)+"/"+tt.rev+"/"+tt.subdir, runTest(tt))
		}
	}
}

var hgmap = map[string]string{
	"HEAD": "41964ddce1180313bdc01d0a39a2813344d6261d", // not tip due to bad hgrepo1 conversion
	"9d02800338b8a55be062c838d1f02e0c5780b9eb": "8f49ee7a6ddcdec6f0112d9dca48d4a2e4c3c09e",
	"76a00fb249b7f93091bc2c89a789dab1fc1bc26f": "88fde824ec8b41a76baa16b7e84212cee9f3edd0",
	"ede458df7cd0fdca520df19a33158086a8a68e81": "41964ddce1180313bdc01d0a39a2813344d6261d",
	"97f6aa59c81c623494825b43d39e445566e429a4": "c0cbbfb24c7c3c50c35c7b88e7db777da4ff625d",
}

func TestStat(t *testing.T) {
	t.Parallel()

	type statTest struct {
		repo string
		rev  string
		err  string
		info *RevInfo
	}
	runTest := func(tt statTest) func(*testing.T) {
		return func(t *testing.T) {
			t.Parallel()
			ctx := testContext(t)

			r, err := testRepo(ctx, t, tt.repo)
			if err != nil {
				t.Fatal(err)
			}
			info, err := r.Stat(ctx, tt.rev)
			if err != nil {
				if tt.err == "" {
					t.Fatalf("Stat: unexpected error %v", err)
				}
				if !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("Stat: wrong error %q, want %q", err, tt.err)
				}
				if info != nil && info.Origin == nil {
					t.Errorf("Stat: non-nil info with nil Origin with error %q", err)
				}
				return
			}
			info.Origin = nil // TestLatest and ../../../testdata/script/reuse_git.txt test Origin well enough
			if !reflect.DeepEqual(info, tt.info) {
				t.Errorf("Stat: incorrect info\nhave %+v\nwant %+v", *info, *tt.info)
			}
		}
	}

	for _, tt := range []statTest{
		{
			repo: gitrepo1,
			rev:  "HEAD",
			info: &RevInfo{
				Name:    "ede458df7cd0fdca520df19a33158086a8a68e81",
				Short:   "ede458df7cd0",
				Version: "ede458df7cd0fdca520df19a33158086a8a68e81",
				Time:    time.Date(2018, 4, 17, 19, 43, 22, 0, time.UTC),
				Tags:    []string{"v1.2.3", "v1.2.4-annotated"},
			},
		},
		{
			repo: gitrepo1,
			rev:  "v2", // branch
			info: &RevInfo{
				Name:    "9d02800338b8a55be062c838d1f02e0c5780b9eb",
				Short:   "9d02800338b8",
				Version: "9d02800338b8a55be062c838d1f02e0c5780b9eb",
				Time:    time.Date(2018, 4, 17, 20, 00, 32, 0, time.UTC),
				Tags:    []string{"v2.0.2"},
			},
		},
		{
			repo: gitrepo1,
			rev:  "v2.3.4", // badly-named branch (semver should be a tag)
			info: &RevInfo{
				Name:    "76a00fb249b7f93091bc2c89a789dab1fc1bc26f",
				Short:   "76a00fb249b7",
				Version: "76a00fb249b7f93091bc2c89a789dab1fc1bc26f",
				Time:    time.Date(2018, 4, 17, 19, 45, 48, 0, time.UTC),
				Tags:    []string{"v2.0.1", "v2.3"},
			},
		},
		{
			repo: gitrepo1,
			rev:  "v2.3", // badly-named tag (we only respect full semver v2.3.0)
			info: &RevInfo{
				Name:    "76a00fb249b7f93091bc2c89a789dab1fc1bc26f",
				Short:   "76a00fb249b7",
				Version: "v2.3",
				Time:    time.Date(2018, 4, 17, 19, 45, 48, 0, time.UTC),
				Tags:    []string{"v2.0.1", "v2.3"},
			},
		},
		{
			repo: gitrepo1,
			rev:  "v1.2.3", // tag
			info: &RevInfo{
				Name:    "ede458df7cd0fdca520df19a33158086a8a68e81",
				Short:   "ede458df7cd0",
				Version: "v1.2.3",
				Time:    time.Date(2018, 4, 17, 19, 43, 22, 0, time.UTC),
				Tags:    []string{"v1.2.3", "v1.2.4-annotated"},
			},
		},
		{
			repo: gitrepo1,
			rev:  "ede458df", // hash prefix in refs
			info: &RevInfo{
				Name:    "ede458df7cd0fdca520df19a33158086a8a68e81",
				Short:   "ede458df7cd0",
				Version: "ede458df7cd0fdca520df19a33158086a8a68e81",
				Time:    time.Date(2018, 4, 17, 19, 43, 22, 0, time.UTC),
				Tags:    []string{"v1.2.3", "v1.2.4-annotated"},
			},
		},
		{
			repo: gitrepo1,
			rev:  "97f6aa59", // hash prefix not in refs
			info: &RevInfo{
				Name:    "97f6aa59c81c623494825b43d39e445566e429a4",
				Short:   "97f6aa59c81c",
				Version: "97f6aa59c81c623494825b43d39e445566e429a4",
				Time:    time.Date(2018, 4, 17, 20, 0, 19, 0, time.UTC),
			},
		},
		{
			repo: gitrepo1,
			rev:  "v1.2.4-annotated", // annotated tag uses unwrapped commit hash
			info: &RevInfo{
				Name:    "ede458df7cd0fdca520df19a33158086a8a68e81",
				Short:   "ede458df7cd0",
				Version: "v1.2.4-annotated",
				Time:    time.Date(2018, 4, 17, 19, 43, 22, 0, time.UTC),
				Tags:    []string{"v1.2.3", "v1.2.4-annotated"},
			},
		},
		{
			repo: gitrepo1,
			rev:  "aaaaaaaaab",
			err:  "unknown revision",
		},
	} {
		t.Run(path.Base(tt.repo)+"/"+tt.rev, runTest(tt))
		if tt.repo == gitrepo1 {
			for _, tt.repo = range altRepos() {
				old := tt
				var m map[string]string
				if tt.repo == hgrepo1 {
					m = hgmap
				}
				if tt.info != nil {
					info := *tt.info
					tt.info = &info
					tt.info.Name = remap(tt.info.Name, m)
					tt.info.Version = remap(tt.info.Version, m)
					tt.info.Short = remap(tt.info.Short, m)
				}
				tt.rev = remap(tt.rev, m)
				t.Run(path.Base(tt.repo)+"/"+tt.rev, runTest(tt))
				tt = old
			}
		}
	}
}

func remap(name string, m map[string]string) string {
	if m[name] != "" {
		return m[name]
	}
	if AllHex(name) {
		for k, v := range m {
			if strings.HasPrefix(k, name) {
				return v[:len(name)]
			}
		}
	}
	return name
}

"""



```