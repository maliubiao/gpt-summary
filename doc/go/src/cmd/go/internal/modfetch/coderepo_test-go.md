Response: Let's break down the thought process for analyzing this Go code and answering the user's request.

1. **Understanding the Goal:** The user wants to understand the functionality of the provided Go code, which is a test file (`coderepo_test.go`). They are particularly interested in *what* it tests and *how* it tests it.

2. **Initial Scan - Identifying Key Components:**  A quick glance reveals:
    * **Package Declaration:** `package modfetch` suggests it's related to fetching modules.
    * **Imports:**  These provide clues about the functionalities being tested: `archive/zip`, `context`, `crypto/sha256`, `flag`, `internal/testenv`, `io`, `log`, `os`, `path/filepath`, `reflect`, `strings`, `testing`, `time`, and crucially, `cmd/go/internal/modfetch` and `cmd/go/internal/vcweb/vcstest`. The `golang.org/x/mod/sumdb/dirhash` import points to checks related to module content integrity.
    * **`TestMain` and `testMain`:** These are standard test setup functions in Go. `testMain` configures the testing environment by setting `GOPROXY` and `GOSUMDB`, and creating a temporary module cache. It also sets up a mock VCS server using `vcstest.NewServer()`. This immediately tells us the tests are likely interacting with remote repositories.
    * **Constants and Variables:** `vgotest1git`, `vgotest1hg`, `altVgotests` indicate tests involving Git and Mercurial repositories. The `codeRepoTest` struct and `codeRepoTests` slice are the core of the test definitions, listing various scenarios.
    * **Test Functions:** `TestCodeRepo` and `TestCodeRepoVersions` are the main test functions. `TestLatest` is another one. `TestNonCanonicalSemver` is a specific test case.

3. **Deep Dive into `codeRepoTest` and `codeRepoTests`:** This is where the core understanding lies. The `codeRepoTest` struct defines the parameters for a single test case:
    * `vcs`: Version control system (e.g., "git").
    * `path`: Module path.
    * `mpath`: Expected module path (can differ in some cases).
    * `rev`: Revision to test (tag, commit hash, branch).
    * `err`: Expected error message.
    * `version`: Expected resolved version.
    * `name`: Expected commit name/hash.
    * `short`: Expected short commit hash.
    * `time`: Expected commit time.
    * `gomod`: Expected content of the `go.mod` file.
    * `gomodErr`: Expected error when fetching `go.mod`.
    * `zip`: Expected files in the downloaded zip archive.
    * `zipErr`: Expected error during zip download.
    * `zipSum`: Expected checksum of the zip archive.
    * `zipFileHash`: Expected hash of the downloaded zip file.

    The `codeRepoTests` slice is a large collection of these test cases, covering different scenarios: valid versions, invalid versions, different VCS types, `go.mod` file presence/absence, subdirectory modules, redirects, and more.

4. **Analyzing Test Functions:**
    * **`TestCodeRepo`:** This is the primary test function. It iterates through `codeRepoTests`. For each test case:
        * It calls `modfetch.Lookup()` to get a `codehost.Repo` implementation. This is the *functionality being tested*.
        * It calls `repo.Stat()` to get information about a specific revision. It checks the returned `info` against the expected values in the test case.
        * It calls `repo.GoMod()` to fetch the `go.mod` file and compares its content or error.
        * It calls `repo.Zip()` to download the module as a zip file and checks its contents, checksum, and file hash.
    * **`TestCodeRepoVersions`:** This tests the `repo.Versions()` method, checking if it correctly lists available versions for a given module path and prefix.
    * **`TestLatest`:** This tests the `repo.Latest()` method, verifying that it retrieves the latest available version.
    * **`TestNonCanonicalSemver`:** This tests a specific scenario involving handling non-canonical semantic versions.

5. **Inferring the Go Language Feature:** Based on the package name (`modfetch`), the import of `cmd/go/internal/modfetch`, and the methods being tested (`Stat`, `GoMod`, `Zip`, `Versions`, `Latest`), it's clear that this code tests the **module fetching functionality** of the Go command. Specifically, it tests how the `go` command interacts with remote repositories (Git, Mercurial, etc.) to retrieve module information and source code.

6. **Code Example:**  To illustrate, the `repo.Stat()` function likely corresponds to the `go list -m -versions <module>@<version>` command, which resolves a specific module version. `repo.GoMod()` relates to reading the `go.mod` file, which the `go` command does internally. `repo.Zip()` is akin to how the `go mod download` command fetches the source code.

7. **Command-Line Arguments:** The `TestMain` function uses `flag.Parse()`, indicating that these tests can potentially be influenced by command-line flags. However, the provided code snippet doesn't explicitly define or use any specific flags. The important part is that `testMain` *sets* environment variables like `GOPROXY` and `GOSUMDB`, which *directly* affects how the module fetching mechanism works in the `go` command.

8. **Common Mistakes:**  The test cases themselves highlight potential issues:
    * **Incorrect `go.mod` Path:**  Mismatches between the module path in `go.mod` and the directory structure (especially with versioned modules like `/v2`).
    * **Invalid Pseudo-Versions:**  Using pseudo-versions incorrectly.
    * **Version Tagging Issues:** Problems with tags that are not valid semantic versions or have incorrect suffixes like `+incompatible`.
    * **Missing `go.mod` Files:** Trying to access versions in subdirectories without a `go.mod` file in that subdirectory.

9. **Structuring the Answer:**  Organize the findings logically based on the user's request:
    * Functionalities of the test file.
    * Go language feature being tested.
    * Code examples.
    * Command-line argument handling (focus on the environment variables set).
    * Common mistakes (derived from the test cases).

10. **Refinement:** Review the answer for clarity, accuracy, and completeness. Ensure the code examples are illustrative and the explanations are easy to understand. For instance, clarify that the tests use a *mock* server, not live remote repositories directly (although they might require network access for some tests).

By following these steps, we can thoroughly analyze the provided Go test code and provide a comprehensive and helpful answer to the user's request.
这段代码是 Go 语言标准库中 `cmd/go` 工具的一部分，专门用于测试 **模块依赖拉取 (module fetching)** 的功能。更具体地说，它测试了 `internal/modfetch/coderepo.go` 中关于如何从不同的代码仓库（如 Git 和 Mercurial）获取模块信息和源代码的功能。

以下是它的主要功能：

1. **测试从不同 VCS (版本控制系统) 获取模块信息:**  `codeRepoTests` 变量定义了一系列测试用例，每个用例指定了一个 VCS 类型 (`vcs`)，模块路径 (`path`)，以及期望的模块信息，例如版本号 (`version`)，提交哈希 (`name`)，提交时间 (`time`) 等。测试会调用 `modfetch.Lookup` 函数来获取对应代码仓库的接口，然后调用其 `Stat` 方法来获取指定 revision 的信息，并与预期结果进行比较。

2. **测试获取 `go.mod` 文件内容:**  测试用例中可以指定期望的 `go.mod` 文件内容 (`gomod`) 或获取 `go.mod` 文件时期望发生的错误 (`gomodErr`)。测试会调用代码仓库接口的 `GoMod` 方法来获取 `go.mod` 文件内容并进行验证。

3. **测试下载模块的 ZIP 文件:**  测试用例可以指定期望的 ZIP 文件中包含的文件列表 (`zip`)，期望的 ZIP 文件校验和 (`zipSum`) 和文件哈希 (`zipFileHash`)，或者下载 ZIP 文件时期望发生的错误 (`zipErr`)。测试会调用代码仓库接口的 `Zip` 方法下载 ZIP 文件，并验证其内容和校验和。

4. **测试列出模块的版本:** `codeRepoVersionsTests` 变量定义了一系列测试用例，用于测试代码仓库接口的 `Versions` 方法，该方法用于列出模块可用的版本。测试用例指定了模块路径和可选的版本前缀 (`prefix`)，以及期望返回的版本列表 (`versions`)。

5. **测试获取模块的最新版本:** `latestTests` 变量定义了一系列测试用例，用于测试代码仓库接口的 `Latest` 方法，该方法用于获取模块的最新版本信息。

6. **模拟不同的代码托管平台行为:**  通过 `vcstest.NewServer()` 创建一个模拟的 VCS 服务器，用于模拟 GitHub、Go Modules Proxy 等代码托管平台的行为，以便在测试环境中隔离网络依赖。

**它可以推理出是 Go 语言模块依赖拉取功能的实现。**

**Go 代码举例说明:**

假设我们要获取 `github.com/rsc/vgotest1` 仓库中 `v1.0.0` 版本的信息和 ZIP 文件。代码中会执行类似以下的操作：

```go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"cmd/go/internal/cfg"
	"cmd/go/internal/modfetch"
)

func main() {
	cfg.GOPROXY = "direct" // 直接连接仓库
	cfg.GOSUMDB = "off"   // 关闭校验和数据库

	tmpDir, err := os.MkdirTemp("", "modfetch-test-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	cfg.GOMODCACHE = filepath.Join(tmpDir, "modcache")
	if err := os.MkdirAll(cfg.GOMODCACHE, 0755); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	repo := modfetch.Lookup(ctx, "direct", "github.com/rsc/vgotest1")

	// 获取 v1.0.0 版本的信息
	info, err := repo.Stat(ctx, "v1.0.0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Version: %s, Commit: %s, Time: %v\n", info.Version, info.Name, info.Time)

	// 下载 v1.0.0 版本的 ZIP 文件
	zipFile, err := os.CreateTemp(tmpDir, "vgotest1-v1.0.0.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer zipFile.Close()

	err = repo.Zip(ctx, zipFile, "v1.0.0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ZIP file downloaded to: %s\n", zipFile.Name())

	// 获取 v1.0.0 版本的 go.mod 文件
	gomodContent, err := repo.GoMod(ctx, "v1.0.0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("go.mod content:\n%s\n", string(gomodContent))
}
```

**假设的输入与输出：**

这个测试文件本身不直接接收用户输入。它的“输入”来自于 `codeRepoTests` 和其他类似的变量中定义的测试用例。

对于上面的代码示例，假设网络连接正常，并且 `github.com/rsc/vgotest1` 仓库存在且可以访问，则输出可能如下：

```
Version: v1.0.0, Commit: 80d85c5d4d17598a0e9055e7c175a32b415d6128, Time: 2018-02-19 23:10:06 +0000 UTC
ZIP file downloaded to: /tmp/modfetch-test-xxxxx/vgotest1-v1.0.0.zip
go.mod content:
module "github.com/rsc/vgotest1" // root go.mod

go 1.10
```

**命令行参数的具体处理:**

`TestMain` 函数中调用了 `flag.Parse()`，这意味着这个测试程序可以接受一些标准的 Go 测试标志，例如：

* `-test.run <regexp>`:  运行匹配指定正则表达式的测试用例。
* `-test.v`:  输出更详细的测试日志。
* `-test.short`:  运行时间较短的测试用例。
* `-test.timeout <duration>`: 设置测试超时时间。

这些是 Go 语言测试框架提供的标准标志，用于控制测试的执行方式。在这个特定的测试文件中，这些标志主要用于控制哪些测试用例会被执行以及输出的详细程度。

**使用者易犯错的点:**

这个文件是 Go 语言内部的测试代码，直接的使用者是 Go 语言的开发者。 对于普通的 Go 模块使用者来说，不太会直接接触到这段代码。 然而，从这些测试用例中，我们可以推断出 Go 模块使用者在进行模块依赖管理时容易犯的错误：

1. **`go.mod` 文件中的模块路径不正确:**  测试用例中包含了对 `go.mod` 文件中模块路径的各种验证，例如 `github.com/rsc/vgotest1/v2/go.mod has non-.../v2 module path` 这样的错误，说明如果 `go.mod` 文件中的 `module` 声明与模块所在的路径不匹配，会导致错误。

   * **例子:**  假设一个模块的路径是 `example.com/my/module/v2`，但是 `go.mod` 文件中声明的是 `module example.com/my/module`，则会导致错误。

2. **版本号不规范:**  测试用例中包含了对各种版本号格式的验证，包括语义化版本和预发布版本等。如果指定的版本号不符合规范，可能会导致拉取失败。

   * **例子:**  使用类似 `v1.0` 这样的不完整的语义化版本号可能导致问题，应该使用 `v1.0.0`。

3. **依赖的模块不存在或者不可访问:** 虽然测试代码模拟了 VCS 服务器，但在实际使用中，如果依赖的模块仓库不存在、网络不可达或者权限不足，也会导致拉取失败。

4. **GOPROXY 配置不正确:**  `TestMain` 中设置了 `cfg.GOPROXY = "direct"`，这意味着测试直接连接到代码仓库。但在实际使用中，如果 `GOPROXY` 配置不正确，例如指向了一个不可用的代理服务器，也会导致模块拉取失败。

5. **GOSUMDB 配置不当:**  `TestMain` 中设置了 `cfg.GOSUMDB = "off"`，关闭了校验和数据库。在实际使用中，如果 `GOSUMDB` 配置不当，例如无法连接到校验和数据库，可能会导致模块拉取失败或安全风险。

总而言之，这段代码是 `go` 命令用于测试其模块依赖拉取功能的核心测试文件，通过大量的测试用例覆盖了各种场景，确保 `go` 命令能够正确地从不同的代码仓库获取模块信息和源代码。从测试用例中，我们也能了解到 Go 模块使用者在进行依赖管理时需要注意的一些事项。

### 提示词
```
这是路径为go/src/cmd/go/internal/modfetch/coderepo_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package modfetch

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"hash"
	"internal/testenv"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"cmd/go/internal/cfg"
	"cmd/go/internal/modfetch/codehost"
	"cmd/go/internal/vcweb/vcstest"

	"golang.org/x/mod/sumdb/dirhash"
)

func TestMain(m *testing.M) {
	flag.Parse()
	if err := testMain(m); err != nil {
		log.Fatal(err)
	}
}

func testMain(m *testing.M) (err error) {

	cfg.GOPROXY = "direct"

	// The sum database is populated using a released version of the go command,
	// but this test may include fixes for additional modules that previously
	// could not be fetched. Since this test isn't executing any of the resolved
	// code, bypass the sum database.
	cfg.GOSUMDB = "off"

	dir, err := os.MkdirTemp("", "gitrepo-test-")
	if err != nil {
		return err
	}
	defer func() {
		if rmErr := os.RemoveAll(dir); err == nil {
			err = rmErr
		}
	}()

	cfg.GOMODCACHE = filepath.Join(dir, "modcache")
	if err := os.Mkdir(cfg.GOMODCACHE, 0755); err != nil {
		return err
	}

	srv, err := vcstest.NewServer()
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := srv.Close(); err == nil {
			err = closeErr
		}
	}()

	m.Run()
	return nil
}

const (
	vgotest1git = "github.com/rsc/vgotest1"
	vgotest1hg  = "vcs-test.golang.org/hg/vgotest1.hg"
)

var altVgotests = map[string]string{
	"hg": vgotest1hg,
}

type codeRepoTest struct {
	vcs         string
	path        string
	mpath       string
	rev         string
	err         string
	version     string
	name        string
	short       string
	time        time.Time
	gomod       string
	gomodErr    string
	zip         []string
	zipErr      string
	zipSum      string
	zipFileHash string
}

var codeRepoTests = []codeRepoTest{
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1",
		rev:     "v0.0.0",
		version: "v0.0.0",
		name:    "80d85c5d4d17598a0e9055e7c175a32b415d6128",
		short:   "80d85c5d4d17",
		time:    time.Date(2018, 2, 19, 23, 10, 6, 0, time.UTC),
		zip: []string{
			"LICENSE",
			"README.md",
			"pkg/p.go",
		},
		zipSum:      "h1:zVEjciLdlk/TPWCOyZo7k24T+tOKRQC+u8MKq/xS80I=",
		zipFileHash: "738a00ddbfe8c329dce6b48e1f23c8e22a92db50f3cfb2653caa0d62676bc09c",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1",
		rev:     "v0.0.0-20180219231006-80d85c5d4d17",
		version: "v0.0.0-20180219231006-80d85c5d4d17",
		name:    "80d85c5d4d17598a0e9055e7c175a32b415d6128",
		short:   "80d85c5d4d17",
		time:    time.Date(2018, 2, 19, 23, 10, 6, 0, time.UTC),
		zip: []string{
			"LICENSE",
			"README.md",
			"pkg/p.go",
		},
		zipSum:      "h1:nOznk2xKsLGkTnXe0q9t1Ewt9jxK+oadtafSUqHM3Ec=",
		zipFileHash: "bacb08f391e29d2eaaef8281b5c129ee6d890e608ee65877e0003c0181a766c8",
	},
	{
		vcs:  "git",
		path: "github.com/rsc/vgotest1",
		rev:  "v0.0.1-0.20180219231006-80d85c5d4d17",
		err:  `github.com/rsc/vgotest1@v0.0.1-0.20180219231006-80d85c5d4d17: invalid pseudo-version: tag (v0.0.0) found on revision 80d85c5d4d17 is already canonical, so should not be replaced with a pseudo-version derived from that tag`,
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1",
		rev:     "v1.0.0",
		version: "v1.0.0",
		name:    "80d85c5d4d17598a0e9055e7c175a32b415d6128",
		short:   "80d85c5d4d17",
		time:    time.Date(2018, 2, 19, 23, 10, 6, 0, time.UTC),
		zip: []string{
			"LICENSE",
			"README.md",
			"pkg/p.go",
		},
		zipSum:      "h1:e040hOoWGeuJLawDjK9DW6med+cz9FxMFYDMOVG8ctQ=",
		zipFileHash: "74caab65cfbea427c341fa815f3bb0378681d8f0e3cf62a7f207014263ec7be3",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1/v2",
		rev:     "v2.0.0",
		version: "v2.0.0",
		name:    "45f53230a74ad275c7127e117ac46914c8126160",
		short:   "45f53230a74a",
		time:    time.Date(2018, 7, 19, 1, 21, 27, 0, time.UTC),
		err:     "missing github.com/rsc/vgotest1/go.mod and .../v2/go.mod at revision v2.0.0",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1",
		rev:     "80d85c5",
		version: "v1.0.0",
		name:    "80d85c5d4d17598a0e9055e7c175a32b415d6128",
		short:   "80d85c5d4d17",
		time:    time.Date(2018, 2, 19, 23, 10, 6, 0, time.UTC),
		zip: []string{
			"LICENSE",
			"README.md",
			"pkg/p.go",
		},
		zipSum:      "h1:e040hOoWGeuJLawDjK9DW6med+cz9FxMFYDMOVG8ctQ=",
		zipFileHash: "74caab65cfbea427c341fa815f3bb0378681d8f0e3cf62a7f207014263ec7be3",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1",
		rev:     "mytag",
		version: "v1.0.0",
		name:    "80d85c5d4d17598a0e9055e7c175a32b415d6128",
		short:   "80d85c5d4d17",
		time:    time.Date(2018, 2, 19, 23, 10, 6, 0, time.UTC),
		zip: []string{
			"LICENSE",
			"README.md",
			"pkg/p.go",
		},
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1/v2",
		rev:     "45f53230a",
		version: "v2.0.0",
		name:    "45f53230a74ad275c7127e117ac46914c8126160",
		short:   "45f53230a74a",
		time:    time.Date(2018, 7, 19, 1, 21, 27, 0, time.UTC),
		err:     "missing github.com/rsc/vgotest1/go.mod and .../v2/go.mod at revision v2.0.0",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1/v54321",
		rev:     "80d85c5",
		version: "v54321.0.0-20180219231006-80d85c5d4d17",
		name:    "80d85c5d4d17598a0e9055e7c175a32b415d6128",
		short:   "80d85c5d4d17",
		time:    time.Date(2018, 2, 19, 23, 10, 6, 0, time.UTC),
		err:     "missing github.com/rsc/vgotest1/go.mod and .../v54321/go.mod at revision 80d85c5d4d17",
	},
	{
		vcs:  "git",
		path: "github.com/rsc/vgotest1/submod",
		rev:  "v1.0.0",
		err:  "unknown revision submod/v1.0.0",
	},
	{
		vcs:  "git",
		path: "github.com/rsc/vgotest1/submod",
		rev:  "v1.0.3",
		err:  "unknown revision submod/v1.0.3",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1/submod",
		rev:     "v1.0.4",
		version: "v1.0.4",
		name:    "8afe2b2efed96e0880ecd2a69b98a53b8c2738b6",
		short:   "8afe2b2efed9",
		time:    time.Date(2018, 2, 19, 23, 12, 7, 0, time.UTC),
		gomod:   "module \"github.com/vgotest1/submod\" // submod/go.mod\n",
		zip: []string{
			"go.mod",
			"pkg/p.go",
			"LICENSE",
		},
		zipSum:      "h1:iMsJ/9uQsk6MnZNnJK311f11QiSlmN92Q2aSjCywuJY=",
		zipFileHash: "95801bfa69c5197ae809af512946d22f22850068527cd78100ae3f176bc8043b",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1",
		rev:     "v1.1.0",
		version: "v1.1.0",
		name:    "b769f2de407a4db81af9c5de0a06016d60d2ea09",
		short:   "b769f2de407a",
		time:    time.Date(2018, 2, 19, 23, 13, 36, 0, time.UTC),
		gomod:   "module \"github.com/rsc/vgotest1\" // root go.mod\nrequire \"github.com/rsc/vgotest1/submod\" v1.0.5\n",
		zip: []string{
			"LICENSE",
			"README.md",
			"go.mod",
			"pkg/p.go",
		},
		zipSum:      "h1:M69k7q+8bQ+QUpHov45Z/NoR8rj3DsQJUnXLWvf01+Q=",
		zipFileHash: "58af45fb248d320ea471f568e006379e2b8d71d6d1663f9b19b2e00fd9ac9265",
	},
	{
		vcs:         "git",
		path:        "github.com/rsc/vgotest1/v2",
		rev:         "v2.0.1",
		version:     "v2.0.1",
		name:        "ea65f87c8f52c15ea68f3bdd9925ef17e20d91e9",
		short:       "ea65f87c8f52",
		time:        time.Date(2018, 2, 19, 23, 14, 23, 0, time.UTC),
		gomod:       "module \"github.com/rsc/vgotest1/v2\" // root go.mod\n",
		zipSum:      "h1:QmgYy/zt+uoWhDpcsgrSVzYFvKtBEjl5zT/FRz9GTzA=",
		zipFileHash: "1aedf1546d322a0121879ddfd6d0e8bfbd916d2cafbeb538ddb440e04b04b9ef",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1/v2",
		rev:     "v2.0.3",
		version: "v2.0.3",
		name:    "f18795870fb14388a21ef3ebc1d75911c8694f31",
		short:   "f18795870fb1",
		time:    time.Date(2018, 2, 19, 23, 16, 4, 0, time.UTC),
		err:     "github.com/rsc/vgotest1/v2/go.mod has non-.../v2 module path \"github.com/rsc/vgotest\" at revision v2.0.3",
	},
	{
		vcs:     "git",
		path:    "github.com/rsc/vgotest1/v2",
		rev:     "v2.0.4",
		version: "v2.0.4",
		name:    "1f863feb76bc7029b78b21c5375644838962f88d",
		short:   "1f863feb76bc",
		time:    time.Date(2018, 2, 20, 0, 3, 38, 0, time.UTC),
		err:     "github.com/rsc/vgotest1/go.mod and .../v2/go.mod both have .../v2 module paths at revision v2.0.4",
	},
	{
		vcs:         "git",
		path:        "github.com/rsc/vgotest1/v2",
		rev:         "v2.0.5",
		version:     "v2.0.5",
		name:        "2f615117ce481c8efef46e0cc0b4b4dccfac8fea",
		short:       "2f615117ce48",
		time:        time.Date(2018, 2, 20, 0, 3, 59, 0, time.UTC),
		gomod:       "module \"github.com/rsc/vgotest1/v2\" // v2/go.mod\n",
		zipSum:      "h1:RIEb9q1SUSEQOzMn0zfl/LQxGFWlhWEAdeEguf1MLGU=",
		zipFileHash: "7d92c2c328c5e9b0694101353705d5843746ec1d93a1e986d0da54c8a14dfe6d",
	},
	{
		// redirect to github
		vcs:         "git",
		path:        "rsc.io/quote",
		rev:         "v1.0.0",
		version:     "v1.0.0",
		name:        "f488df80bcdbd3e5bafdc24ad7d1e79e83edd7e6",
		short:       "f488df80bcdb",
		time:        time.Date(2018, 2, 14, 0, 45, 20, 0, time.UTC),
		gomod:       "module \"rsc.io/quote\"\n",
		zipSum:      "h1:haUSojyo3j2M9g7CEUFG8Na09dtn7QKxvPGaPVQdGwM=",
		zipFileHash: "5c08ba2c09a364f93704aaa780e7504346102c6ef4fe1333a11f09904a732078",
	},
	{
		// redirect to static hosting proxy
		vcs:     "mod",
		path:    "swtch.com/testmod",
		rev:     "v1.0.0",
		version: "v1.0.0",
		// NO name or short - we intentionally ignore those in the proxy protocol
		time:  time.Date(1972, 7, 18, 12, 34, 56, 0, time.UTC),
		gomod: "module \"swtch.com/testmod\"\n",
	},
	{
		// redirect to googlesource
		vcs:         "git",
		path:        "golang.org/x/text",
		rev:         "4e4a3210bb",
		version:     "v0.3.1-0.20180208041248-4e4a3210bb54",
		name:        "4e4a3210bb54bb31f6ab2cdca2edcc0b50c420c1",
		short:       "4e4a3210bb54",
		time:        time.Date(2018, 2, 8, 4, 12, 48, 0, time.UTC),
		zipSum:      "h1:Yxu6pHX9X2RECiuw/Q5/4uvajuaowck8zOFKXgbfNBk=",
		zipFileHash: "ac2c165a5c10aa5a7545dea60a08e019270b982fa6c8bdcb5943931de64922fe",
	},
	{
		vcs:         "git",
		path:        "github.com/pkg/errors",
		rev:         "v0.8.0",
		version:     "v0.8.0",
		name:        "645ef00459ed84a119197bfb8d8205042c6df63d",
		short:       "645ef00459ed",
		time:        time.Date(2016, 9, 29, 1, 48, 1, 0, time.UTC),
		zipSum:      "h1:WdK/asTD0HN+q6hsWO3/vpuAkAr+tw6aNJNDFFf0+qw=",
		zipFileHash: "e4fa69ba057356614edbc1da881a7d3ebb688505be49f65965686bcb859e2fae",
	},
	{
		// package in subdirectory - custom domain
		// In general we can't reject these definitively in Lookup,
		// but gopkg.in is special.
		vcs:  "git",
		path: "gopkg.in/yaml.v2/abc",
		err:  "invalid module path \"gopkg.in/yaml.v2/abc\"",
	},
	{
		// package in subdirectory - github
		// Because it's a package, Stat should fail entirely.
		vcs:  "git",
		path: "github.com/rsc/quote/buggy",
		rev:  "c4d4236f",
		err:  "missing github.com/rsc/quote/buggy/go.mod at revision c4d4236f9242",
	},
	{
		vcs:         "git",
		path:        "gopkg.in/yaml.v2",
		rev:         "d670f940",
		version:     "v2.0.0",
		name:        "d670f9405373e636a5a2765eea47fac0c9bc91a4",
		short:       "d670f9405373",
		time:        time.Date(2018, 1, 9, 11, 43, 31, 0, time.UTC),
		gomod:       "module gopkg.in/yaml.v2\n",
		zipSum:      "h1:uUkhRGrsEyx/laRdeS6YIQKIys8pg+lRSRdVMTYjivs=",
		zipFileHash: "7b0a141b1b0b49772ab4eecfd11dfd6609a94a5e868cab04a3abb1861ffaa877",
	},
	{
		vcs:         "git",
		path:        "gopkg.in/check.v1",
		rev:         "20d25e280405",
		version:     "v1.0.0-20161208181325-20d25e280405",
		name:        "20d25e2804050c1cd24a7eea1e7a6447dd0e74ec",
		short:       "20d25e280405",
		time:        time.Date(2016, 12, 8, 18, 13, 25, 0, time.UTC),
		gomod:       "module gopkg.in/check.v1\n",
		zipSum:      "h1:829vOVxxusYHC+IqBtkX5mbKtsY9fheQiQn0MZRVLfQ=",
		zipFileHash: "9e7cb3f4f1e66d722306442b0dbe1f6f43d74d1736d54c510537bdfb1d6f432f",
	},
	{
		vcs:         "git",
		path:        "vcs-test.golang.org/go/mod/gitrepo1",
		rev:         "master",
		version:     "v1.2.4-annotated",
		name:        "ede458df7cd0fdca520df19a33158086a8a68e81",
		short:       "ede458df7cd0",
		time:        time.Date(2018, 4, 17, 19, 43, 22, 0, time.UTC),
		gomod:       "module vcs-test.golang.org/go/mod/gitrepo1\n",
		zipSum:      "h1:YJYZRsM9BHFTlVr8YADjT0cJH8uFIDtoc5NLiVqZEx8=",
		zipFileHash: "c15e49d58b7a4c37966cbe5bc01a0330cd5f2927e990e1839bda1d407766d9c5",
	},
	{
		vcs:  "git",
		path: "gopkg.in/natefinch/lumberjack.v2",
		// This repo has a v2.1 tag.
		// We only allow semver references to tags that are fully qualified, as in v2.1.0.
		// Because we can't record v2.1.0 (the actual tag is v2.1), we record a pseudo-version
		// instead, same as if the tag were any other non-version-looking string.
		// We use a v2 pseudo-version here because of the .v2 in the path, not because
		// of the v2 in the rev.
		rev:     "v2.1", // non-canonical semantic version turns into pseudo-version
		version: "v2.0.0-20170531160350-a96e63847dc3",
		name:    "a96e63847dc3c67d17befa69c303767e2f84e54f",
		short:   "a96e63847dc3",
		time:    time.Date(2017, 5, 31, 16, 3, 50, 0, time.UTC),
		gomod:   "module gopkg.in/natefinch/lumberjack.v2\n",
	},
	{
		vcs:         "git",
		path:        "vcs-test.golang.org/go/v2module/v2",
		rev:         "v2.0.0",
		version:     "v2.0.0",
		name:        "203b91c896acd173aa719e4cdcb7d463c4b090fa",
		short:       "203b91c896ac",
		time:        time.Date(2019, 4, 3, 15, 52, 15, 0, time.UTC),
		gomod:       "module vcs-test.golang.org/go/v2module/v2\n\ngo 1.12\n",
		zipSum:      "h1:JItBZ+gwA5WvtZEGEbuDL4lUttGtLrs53lmdurq3bOg=",
		zipFileHash: "9ea9ae1673cffcc44b7fdd3cc89953d68c102449b46c982dbf085e4f2e394da5",
	},
	{
		// Git branch with a semver name, +incompatible version, and no go.mod file.
		vcs:  "git",
		path: "vcs-test.golang.org/go/mod/gitrepo1",
		rev:  "v2.3.4+incompatible",
		err:  `resolves to version v2.0.1+incompatible (v2.3.4 is not a tag)`,
	},
	{
		// Git branch with a semver name, matching go.mod file, and compatible version.
		vcs:  "git",
		path: "vcs-test.golang.org/git/semver-branch.git",
		rev:  "v1.0.0",
		err:  `resolves to version v0.1.1-0.20220202191944-09c4d8f6938c (v1.0.0 is not a tag)`,
	},
	{
		// Git branch with a semver name, matching go.mod file, and disallowed +incompatible version.
		// The version/tag mismatch takes precedence over the +incompatible mismatched.
		vcs:  "git",
		path: "vcs-test.golang.org/git/semver-branch.git",
		rev:  "v2.0.0+incompatible",
		err:  `resolves to version v0.1.0 (v2.0.0 is not a tag)`,
	},
	{
		// Git branch with a semver name, matching go.mod file, and mismatched version.
		// The version/tag mismatch takes precedence over the +incompatible mismatched.
		vcs:  "git",
		path: "vcs-test.golang.org/git/semver-branch.git",
		rev:  "v2.0.0",
		err:  `resolves to version v0.1.0 (v2.0.0 is not a tag)`,
	},
	{
		// v3.0.0-devel is the same as tag v4.0.0-beta.1, but v4.0.0-beta.1 would
		// not be allowed because it is incompatible and a go.mod file exists.
		// The error message should refer to a valid pseudo-version, not the
		// unusable semver tag.
		vcs:  "git",
		path: "vcs-test.golang.org/git/semver-branch.git",
		rev:  "v3.0.0-devel",
		err:  `resolves to version v0.1.1-0.20220203155313-d59622f6e4d7 (v3.0.0-devel is not a tag)`,
	},

	// If v2/go.mod exists, then we should prefer to match the "v2"
	// pseudo-versions to the nested module, and resolve the module in the parent
	// directory to only compatible versions.
	//
	// However (https://go.dev/issue/51324), previous versions of the 'go' command
	// didn't always do so, so if the user explicitly requests a +incompatible
	// version (as would be present in an existing go.mod file), we should
	// continue to allow it.
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/v2sub.git",
		rev:     "80beb17a1603",
		version: "v0.0.0-20220222205507-80beb17a1603",
		name:    "80beb17a16036f17a5aedd1bb5bd6d407b3c6dc5",
		short:   "80beb17a1603",
		time:    time.Date(2022, 2, 22, 20, 55, 7, 0, time.UTC),
	},
	{
		vcs:  "git",
		path: "vcs-test.golang.org/git/v2sub.git",
		rev:  "v2.0.0",
		err:  `module contains a go.mod file, so module path must match major version ("vcs-test.golang.org/git/v2sub.git/v2")`,
	},
	{
		vcs:  "git",
		path: "vcs-test.golang.org/git/v2sub.git",
		rev:  "v2.0.1-0.20220222205507-80beb17a1603",
		err:  `module contains a go.mod file, so module path must match major version ("vcs-test.golang.org/git/v2sub.git/v2")`,
	},
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/v2sub.git",
		rev:     "v2.0.0+incompatible",
		version: "v2.0.0+incompatible",
		name:    "5fcd3eaeeb391d399f562fd45a50dac9fc34ae8b",
		short:   "5fcd3eaeeb39",
		time:    time.Date(2022, 2, 22, 20, 53, 33, 0, time.UTC),
	},
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/v2sub.git",
		rev:     "v2.0.1-0.20220222205507-80beb17a1603+incompatible",
		version: "v2.0.1-0.20220222205507-80beb17a1603+incompatible",
		name:    "80beb17a16036f17a5aedd1bb5bd6d407b3c6dc5",
		short:   "80beb17a1603",
		time:    time.Date(2022, 2, 22, 20, 55, 7, 0, time.UTC),
	},

	// A version tag with explicit build metadata is valid but not canonical.
	// It should resolve to a pseudo-version based on the same tag.
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/odd-tags.git",
		rev:     "v0.1.0+build-metadata",
		version: "v0.1.1-0.20220223184835-9d863d525bbf",
		name:    "9d863d525bbfcc8eda09364738c4032393711a56",
		short:   "9d863d525bbf",
		time:    time.Date(2022, 2, 23, 18, 48, 35, 0, time.UTC),
	},
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/odd-tags.git",
		rev:     "9d863d525bbf",
		version: "v0.1.1-0.20220223184835-9d863d525bbf",
		name:    "9d863d525bbfcc8eda09364738c4032393711a56",
		short:   "9d863d525bbf",
		time:    time.Date(2022, 2, 23, 18, 48, 35, 0, time.UTC),
	},
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/odd-tags.git",
		rev:     "latest",
		version: "v0.1.1-0.20220223184835-9d863d525bbf",
		name:    "9d863d525bbfcc8eda09364738c4032393711a56",
		short:   "9d863d525bbf",
		time:    time.Date(2022, 2, 23, 18, 48, 35, 0, time.UTC),
	},

	// A version tag with an erroneous "+incompatible" suffix should resolve using
	// only the prefix before the "+incompatible" suffix, not the "+incompatible"
	// tag itself. (Otherwise, we would potentially have two different commits
	// both named "v2.0.0+incompatible".) However, the tag is still valid semver
	// and can still be used as the base for an unambiguous pseudo-version.
	{
		vcs:  "git",
		path: "vcs-test.golang.org/git/odd-tags.git",
		rev:  "v2.0.0+incompatible",
		err:  `unknown revision v2.0.0`,
	},
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/odd-tags.git",
		rev:     "12d19af20458",
		version: "v2.0.1-0.20220223184802-12d19af20458+incompatible",
		name:    "12d19af204585b0db3d2a876ceddf5b9323f5a4a",
		short:   "12d19af20458",
		time:    time.Date(2022, 2, 23, 18, 48, 2, 0, time.UTC),
	},

	// Similarly, a pseudo-version must resolve to the named commit, even if a tag
	// matching that pseudo-version is present on a *different* commit.
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/odd-tags.git",
		rev:     "v3.0.0-20220223184802-12d19af20458",
		version: "v3.0.0-20220223184802-12d19af20458+incompatible",
		name:    "12d19af204585b0db3d2a876ceddf5b9323f5a4a",
		short:   "12d19af20458",
		time:    time.Date(2022, 2, 23, 18, 48, 2, 0, time.UTC),
	},
}

func TestCodeRepo(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)
	tmpdir := t.TempDir()

	for _, tt := range codeRepoTests {
		f := func(tt codeRepoTest) func(t *testing.T) {
			return func(t *testing.T) {
				if strings.Contains(tt.path, "gopkg.in") {
					testenv.SkipFlaky(t, 54503)
				}

				t.Parallel()
				if tt.vcs != "mod" {
					testenv.MustHaveExecPath(t, tt.vcs)
				}
				ctx := context.Background()

				repo := Lookup(ctx, "direct", tt.path)

				if tt.mpath == "" {
					tt.mpath = tt.path
				}
				if mpath := repo.ModulePath(); mpath != tt.mpath {
					t.Errorf("repo.ModulePath() = %q, want %q", mpath, tt.mpath)
				}

				info, err := repo.Stat(ctx, tt.rev)
				if err != nil {
					if tt.err != "" {
						if !strings.Contains(err.Error(), tt.err) {
							t.Fatalf("repoStat(%q): %v, wanted %q", tt.rev, err, tt.err)
						}
						return
					}
					t.Fatalf("repo.Stat(%q): %v", tt.rev, err)
				}
				if tt.err != "" {
					t.Errorf("repo.Stat(%q): success, wanted error", tt.rev)
				}
				if info.Version != tt.version {
					t.Errorf("info.Version = %q, want %q", info.Version, tt.version)
				}
				if info.Name != tt.name {
					t.Errorf("info.Name = %q, want %q", info.Name, tt.name)
				}
				if info.Short != tt.short {
					t.Errorf("info.Short = %q, want %q", info.Short, tt.short)
				}
				if !info.Time.Equal(tt.time) {
					t.Errorf("info.Time = %v, want %v", info.Time, tt.time)
				}

				if tt.gomod != "" || tt.gomodErr != "" {
					data, err := repo.GoMod(ctx, tt.version)
					if err != nil && tt.gomodErr == "" {
						t.Errorf("repo.GoMod(%q): %v", tt.version, err)
					} else if err != nil && tt.gomodErr != "" {
						if err.Error() != tt.gomodErr {
							t.Errorf("repo.GoMod(%q): %v, want %q", tt.version, err, tt.gomodErr)
						}
					} else if tt.gomodErr != "" {
						t.Errorf("repo.GoMod(%q) = %q, want error %q", tt.version, data, tt.gomodErr)
					} else if string(data) != tt.gomod {
						t.Errorf("repo.GoMod(%q) = %q, want %q", tt.version, data, tt.gomod)
					}
				}

				needHash := !testing.Short() && (tt.zipFileHash != "" || tt.zipSum != "")
				if tt.zip != nil || tt.zipErr != "" || needHash {
					f, err := os.CreateTemp(tmpdir, tt.version+".zip.")
					if err != nil {
						t.Fatalf("os.CreateTemp: %v", err)
					}
					zipfile := f.Name()
					defer func() {
						f.Close()
						os.Remove(zipfile)
					}()

					var w io.Writer
					var h hash.Hash
					if needHash {
						h = sha256.New()
						w = io.MultiWriter(f, h)
					} else {
						w = f
					}
					err = repo.Zip(ctx, w, tt.version)
					f.Close()
					if err != nil {
						if tt.zipErr != "" {
							if err.Error() == tt.zipErr {
								return
							}
							t.Fatalf("repo.Zip(%q): %v, want error %q", tt.version, err, tt.zipErr)
						}
						t.Fatalf("repo.Zip(%q): %v", tt.version, err)
					}
					if tt.zipErr != "" {
						t.Errorf("repo.Zip(%q): success, want error %q", tt.version, tt.zipErr)
					}

					if tt.zip != nil {
						prefix := tt.path + "@" + tt.version + "/"
						z, err := zip.OpenReader(zipfile)
						if err != nil {
							t.Fatalf("open zip %s: %v", zipfile, err)
						}
						var names []string
						for _, file := range z.File {
							if !strings.HasPrefix(file.Name, prefix) {
								t.Errorf("zip entry %v does not start with prefix %v", file.Name, prefix)
								continue
							}
							names = append(names, file.Name[len(prefix):])
						}
						z.Close()
						if !reflect.DeepEqual(names, tt.zip) {
							t.Fatalf("zip = %v\nwant %v\n", names, tt.zip)
						}
					}

					if needHash {
						sum, err := dirhash.HashZip(zipfile, dirhash.Hash1)
						if err != nil {
							t.Errorf("repo.Zip(%q): %v", tt.version, err)
						} else if sum != tt.zipSum {
							t.Errorf("repo.Zip(%q): got file with sum %q, want %q", tt.version, sum, tt.zipSum)
						} else if zipFileHash := hex.EncodeToString(h.Sum(nil)); zipFileHash != tt.zipFileHash {
							t.Errorf("repo.Zip(%q): got file with hash %q, want %q (but content has correct sum)", tt.version, zipFileHash, tt.zipFileHash)
						}
					}
				}
			}
		}
		t.Run(strings.ReplaceAll(tt.path, "/", "_")+"/"+tt.rev, f(tt))
		if strings.HasPrefix(tt.path, vgotest1git) {
			for vcs, alt := range altVgotests {
				altTest := tt
				altTest.vcs = vcs
				altTest.path = alt + strings.TrimPrefix(altTest.path, vgotest1git)
				if strings.HasPrefix(altTest.mpath, vgotest1git) {
					altTest.mpath = alt + strings.TrimPrefix(altTest.mpath, vgotest1git)
				}
				var m map[string]string
				if alt == vgotest1hg {
					m = hgmap
				}
				altTest.version = remap(altTest.version, m)
				altTest.name = remap(altTest.name, m)
				altTest.short = remap(altTest.short, m)
				altTest.rev = remap(altTest.rev, m)
				altTest.err = remap(altTest.err, m)
				altTest.gomodErr = remap(altTest.gomodErr, m)
				altTest.zipErr = remap(altTest.zipErr, m)
				altTest.zipSum = ""
				altTest.zipFileHash = ""
				t.Run(strings.ReplaceAll(altTest.path, "/", "_")+"/"+altTest.rev, f(altTest))
			}
		}
	}
}

var hgmap = map[string]string{
	"github.com/rsc/vgotest1":                  "vcs-test.golang.org/hg/vgotest1.hg",
	"f18795870fb14388a21ef3ebc1d75911c8694f31": "a9ad6d1d14eb544f459f446210c7eb3b009807c6",
	"ea65f87c8f52c15ea68f3bdd9925ef17e20d91e9": "f1fc0f22021b638d073d31c752847e7bf385def7",
	"b769f2de407a4db81af9c5de0a06016d60d2ea09": "92c7eb888b4fac17f1c6bd2e1060a1b881a3b832",
	"8afe2b2efed96e0880ecd2a69b98a53b8c2738b6": "4e58084d459ae7e79c8c2264d0e8e9a92eb5cd44",
	"2f615117ce481c8efef46e0cc0b4b4dccfac8fea": "879ea98f7743c8eff54f59a918f3a24123d1cf46",
	"80d85c5d4d17598a0e9055e7c175a32b415d6128": "e125018e286a4b09061079a81e7b537070b7ff71",
	"1f863feb76bc7029b78b21c5375644838962f88d": "bf63880162304a9337477f3858f5b7e255c75459",
	"45f53230a74ad275c7127e117ac46914c8126160": "814fce58e83abd5bf2a13892e0b0e1198abefcd4",
}

func remap(name string, m map[string]string) string {
	if m[name] != "" {
		return m[name]
	}
	if codehost.AllHex(name) {
		for k, v := range m {
			if strings.HasPrefix(k, name) {
				return v[:len(name)]
			}
		}
	}
	for k, v := range m {
		name = strings.ReplaceAll(name, k, v)
		if codehost.AllHex(k) {
			name = strings.ReplaceAll(name, k[:12], v[:12])
		}
	}
	return name
}

var codeRepoVersionsTests = []struct {
	vcs      string
	path     string
	prefix   string
	versions []string
}{
	{
		vcs:      "git",
		path:     "github.com/rsc/vgotest1",
		versions: []string{"v0.0.0", "v0.0.1", "v1.0.0", "v1.0.1", "v1.0.2", "v1.0.3", "v1.1.0"},
	},
	{
		vcs:      "git",
		path:     "github.com/rsc/vgotest1",
		prefix:   "v1.0",
		versions: []string{"v1.0.0", "v1.0.1", "v1.0.2", "v1.0.3"},
	},
	{
		vcs:      "git",
		path:     "github.com/rsc/vgotest1/v2",
		versions: []string{"v2.0.0", "v2.0.1", "v2.0.2", "v2.0.3", "v2.0.4", "v2.0.5", "v2.0.6"},
	},
	{
		vcs:      "mod",
		path:     "swtch.com/testmod",
		versions: []string{"v1.0.0", "v1.1.1"},
	},
	{
		vcs:      "git",
		path:     "vcs-test.golang.org/git/odd-tags.git",
		versions: nil,
	},
}

func TestCodeRepoVersions(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	for _, tt := range codeRepoVersionsTests {
		tt := tt
		t.Run(strings.ReplaceAll(tt.path, "/", "_"), func(t *testing.T) {
			if strings.Contains(tt.path, "gopkg.in") {
				testenv.SkipFlaky(t, 54503)
			}

			t.Parallel()
			if tt.vcs != "mod" {
				testenv.MustHaveExecPath(t, tt.vcs)
			}
			ctx := context.Background()

			repo := Lookup(ctx, "direct", tt.path)
			list, err := repo.Versions(ctx, tt.prefix)
			if err != nil {
				t.Fatalf("Versions(%q): %v", tt.prefix, err)
			}
			if !reflect.DeepEqual(list.List, tt.versions) {
				t.Fatalf("Versions(%q):\nhave %v\nwant %v", tt.prefix, list, tt.versions)
			}
		})
	}
}

var latestTests = []struct {
	vcs     string
	path    string
	version string
	err     string
}{
	{
		vcs:  "git",
		path: "github.com/rsc/empty",
		err:  "no commits",
	},
	{
		vcs:  "git",
		path: "github.com/rsc/vgotest1",
		err:  `github.com/rsc/vgotest1@v0.0.0-20180219223237-a08abb797a67: invalid version: go.mod has post-v0 module path "github.com/vgotest1/v2" at revision a08abb797a67`,
	},
	{
		vcs:  "git",
		path: "github.com/rsc/vgotest1/v2",
		err:  `github.com/rsc/vgotest1/v2@v2.0.0-20180219223237-a08abb797a67: invalid version: github.com/rsc/vgotest1/go.mod and .../v2/go.mod both have .../v2 module paths at revision a08abb797a67`,
	},
	{
		vcs:  "git",
		path: "github.com/rsc/vgotest1/subdir",
		err:  "github.com/rsc/vgotest1/subdir@v0.0.0-20180219223237-a08abb797a67: invalid version: missing github.com/rsc/vgotest1/subdir/go.mod at revision a08abb797a67",
	},
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/commit-after-tag.git",
		version: "v1.0.1-0.20190715211727-b325d8217783",
	},
	{
		vcs:     "git",
		path:    "vcs-test.golang.org/git/no-tags.git",
		version: "v0.0.0-20190715212047-e706ba1d9f6d",
	},
	{
		vcs:     "mod",
		path:    "swtch.com/testmod",
		version: "v1.1.1",
	},
}

func TestLatest(t *testing.T) {
	testenv.MustHaveExternalNetwork(t)

	for _, tt := range latestTests {
		name := strings.ReplaceAll(tt.path, "/", "_")
		t.Run(name, func(t *testing.T) {
			tt := tt
			t.Parallel()
			if tt.vcs != "mod" {
				testenv.MustHaveExecPath(t, tt.vcs)
			}
			ctx := context.Background()

			repo := Lookup(ctx, "direct", tt.path)
			info, err := repo.Latest(ctx)
			if err != nil {
				if tt.err != "" {
					if err.Error() == tt.err {
						return
					}
					t.Fatalf("Latest(): %v, want %q", err, tt.err)
				}
				t.Fatalf("Latest(): %v", err)
			}
			if tt.err != "" {
				t.Fatalf("Latest() = %v, want error %q", info.Version, tt.err)
			}
			if info.Version != tt.version {
				t.Fatalf("Latest() = %v, want %v", info.Version, tt.version)
			}
		})
	}
}

// fixedTagsRepo is a fake codehost.Repo that returns a fixed list of tags
type fixedTagsRepo struct {
	tags []string
	codehost.Repo
}

func (ch *fixedTagsRepo) Tags(ctx context.Context, prefix string) (*codehost.Tags, error) {
	tags := &codehost.Tags{}
	for _, t := range ch.tags {
		tags.List = append(tags.List, codehost.Tag{Name: t})
	}
	return tags, nil
}

func TestNonCanonicalSemver(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	root := "golang.org/x/issue24476"
	ch := &fixedTagsRepo{
		tags: []string{
			"", "huh?", "1.0.1",
			// what about "version 1 dot dogcow"?
			"v1.🐕.🐄",
			"v1", "v0.1",
			// and one normal one that should pass through
			"v1.0.1",
		},
	}

	cr, err := newCodeRepo(ch, root, root)
	if err != nil {
		t.Fatal(err)
	}

	v, err := cr.Versions(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.List) != 1 || v.List[0] != "v1.0.1" {
		t.Fatal("unexpected versions returned:", v)
	}
}
```