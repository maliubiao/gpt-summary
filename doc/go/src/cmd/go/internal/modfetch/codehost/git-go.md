Response: My thinking process to analyze the provided Go code and generate the response involved these steps:

1. **Understanding the Goal:** The core request is to analyze the `git.go` file within the `cmd/go` toolchain and explain its functionalities, usage, and potential pitfalls. This means going beyond just summarizing the code and delving into the *why* and *how*.

2. **Initial Skim and Key Data Structures:** I first skimmed through the code to get a general idea of its structure and identify key data structures. I noticed the `gitRepo` struct, which clearly holds the core state related to a Git repository. The fields like `remote`, `local`, `dir`, `mu`, `refs`, and `statCache` stood out. The various functions operating on `gitRepo` also provided clues about its purpose.

3. **Identifying Core Functionalities:**  Based on the function names and their parameters, I started grouping them into logical functionalities:
    * **Repository Creation/Initialization:**  `newGitRepo` is the obvious entry point for creating a `gitRepo` instance. I noted the distinction between local and remote repositories.
    * **Remote Information Retrieval:** Functions like `loadRefs`, `Tags`, `Latest`, and `repoSum` are clearly about getting information from the remote Git repository.
    * **Local Repository Interaction:**  `statLocal`, `ReadFile`, `ReadZip`, and potentially parts of `Stat` deal with the local cached copy of the repository.
    * **Revision/Tag Resolution:**  `Stat`, `RecentTag`, `DescendsFrom`, and `findRef` are focused on resolving and comparing different versions/tags within the repository.
    * **Caching and Optimization:**  The use of `sync.Once`, `par.ErrCache`, and the `fetchLevel` indicates efforts to optimize performance by caching and avoiding redundant fetches.
    * **Git Command Execution:** The `runGit` function is a central point for executing Git commands.

4. **Deep Dive into Key Functions:**  I then focused on understanding the logic within the most important functions:
    * **`newGitRepo`:** The distinction between local and remote repositories and the initialization steps (including `git init --bare` and remote adding) were crucial. The handling of Windows long paths was a specific detail to note.
    * **`loadRefs`:** This is fundamental for understanding how the Go toolchain discovers available tags and branches. The interaction with `base.AcquireNet` for network access was important. The error handling, especially for non-existent repositories, was also worth noting.
    * **`Stat` and `stat`:**  The caching mechanism (`par.ErrCache`), the logic for handling different types of revisions (hashes, tags, branches), and the incremental fetching based on `fetchLevel` were key aspects.
    * **`ReadFile`, `ReadZip`:** These functions illustrate how the Go toolchain retrieves specific files or archives from a specific revision. The `ensureGitAttributes` function was a specific detail related to `ReadZip` and zip hash consistency.

5. **Inferring the Go Language Feature:**  By analyzing the functionalities, I concluded that this code implements the **version control system (VCS) integration for Git within the Go module system**. It allows the `go` command to fetch and manage dependencies stored in Git repositories.

6. **Constructing Go Code Examples:** To illustrate the functionality, I created simple Go code snippets demonstrating the key operations: creating a `gitRepo`, fetching tags, and getting information about the latest revision. I aimed for clarity and relevance to the identified functionalities.

7. **Identifying Command-Line Parameter Handling:**  I paid attention to how the code used command-line parameters. The `local` flag in `newGitRepo` and the arguments passed to the `runGit` function were the main points of interest. I explained the significance of the `local` flag.

8. **Recognizing Potential Pitfalls:**  Based on my understanding of the code and how Git works, I identified potential issues users might encounter:
    * **Private repositories:**  The need for authentication and the hints in the error message within `loadRefs` led to this point.
    * **Shallow clones:** The logic around `fetchLevel` and the potential for inconsistencies with shallow clones in `DescendsFrom` were important to highlight.
    * **Network issues:** The reliance on network access for remote repositories made this an obvious point.
    * **Local-only mode:** The restrictions imposed by the `local` flag needed to be explained.

9. **Structuring the Response:** I organized my findings into clear sections based on the prompt's requests: functionality, Go language feature, code examples, command-line parameters, and common mistakes. I used clear and concise language, avoiding unnecessary jargon.

10. **Review and Refinement:** Finally, I reviewed my response to ensure accuracy, completeness, and clarity. I double-checked the code examples and explanations to make sure they were correct and easy to understand. I also made sure to address all parts of the original prompt.
这段代码是 Go 语言 `cmd/go` 工具中 `internal/modfetch/codehost` 包下 `git.go` 文件的一部分。它的主要功能是**处理 Git 仓库，用于模块依赖的获取和管理**。更具体地说，它提供了与远程和本地 Git 仓库交互的能力，以便 `go` 命令可以下载、校验和使用 Git 仓库中定义的 Go 模块。

以下是其功能的详细列表：

**核心功能：**

1. **创建和管理 Git 仓库对象 (`gitRepo`)**:
   - `newGitRepo`:  根据给定的远程 URL 或本地路径创建一个 `gitRepo` 实例。
   - 支持远程仓库 (通过 URL) 和本地仓库 (通过本地文件系统路径) 两种模式。
   - 对于远程仓库，会在本地创建一个工作目录作为缓存，并执行 `git init --bare` 初始化。
   - 可以添加远程仓库地址 `git remote add origin <remote>`。
   - 针对 Windows 系统，可以设置 `core.longpaths` 配置以支持长路径。

2. **获取远程仓库信息:**
   - `loadRefs`:  从远程 Git 仓库获取所有的引用 (refs)，包括分支 (heads) 和标签 (tags)。使用 `git ls-remote` 命令。
   - `Tags`:  获取远程仓库中指定前缀的标签列表。
   - `Latest`: 获取远程仓库的最新提交信息 (通常是 HEAD 指向的提交)。
   - `repoSum`: 计算仓库所有引用的校验和，用于缓存判断仓库状态是否发生变化。

3. **本地仓库操作:**
   - `statLocal`:  从本地 Git 仓库获取指定 revision (commit hash, tag, 分支名) 的详细信息，如提交哈希、提交时间、标签等。使用 `git log` 命令。
   - `ReadFile`: 读取本地 Git 仓库中指定 revision 的某个文件的内容。使用 `git cat-file blob <commit>:<file>` 命令。
   - `ReadZip`: 将本地 Git 仓库中指定 revision 的内容打包成 ZIP 文件。可以指定子目录。使用 `git archive` 命令。

4. **版本和提交信息查询:**
   - `Stat`:  获取指定 revision 的信息。会优先尝试本地仓库，如果本地不存在则会尝试从远程获取。具有缓存机制。
   - `RecentTag`: 查找指定提交之前最近的符合特定前缀和允许规则的标签。
   - `DescendsFrom`: 判断一个提交是否是某个标签的祖先。

5. **校验和缓存:**
   - 使用 `par.ErrCache` 对 `Stat` 方法的结果进行缓存，提高性能。
   - 使用 `repoSum` 计算仓库状态的校验和，用于判断仓库是否发生变化，以便进行更细粒度的缓存控制。

6. **错误处理:**
   - `notExistError`:  包装其他错误，使其在类型上等同于 `fs.ErrNotExist`，用于表示仓库或修订不存在的情况。
   - `UnknownRevisionError`: 表示找不到指定的 revision。

7. **并发控制:**
   - 使用 `sync.Mutex` 和 `lockedfile.Mutex` 来保护对 Git 仓库状态的并发访问，例如在 `fetchLevel` 的更新和 Git 命令的执行过程中。
   - 使用 `sync.Once` 来确保某些操作 (如 `loadRefs` 和 `loadLocalTags`) 只执行一次。

8. **本地 Git 命令执行:**
   - `runGit`:  封装了执行本地 Git 命令的操作。

**推理 Go 语言功能的实现:**

这段代码是 Go 语言 `go` 命令中 **模块 (modules)** 功能的 Git 版本控制系统集成部分。它允许 `go` 命令从 Git 仓库中下载和管理依赖。

**Go 代码示例:**

虽然这段代码本身是 `cmd/go` 工具的一部分，我们无法直接在用户代码中调用它。但是，我们可以通过 `go` 命令的行为来理解其作用。

假设我们有一个 `go.mod` 文件，其中依赖了一个 Git 仓库托管的模块：

```go
module example.com/myapp

go 1.18

require github.com/someuser/somerepo v1.2.3
```

当执行 `go mod download` 或 `go build` 时，`cmd/go` 工具内部就会使用类似 `git.go` 中的代码来完成以下操作：

1. **`newGitRepo`**: 根据 `github.com/someuser/somerepo` 创建一个 `gitRepo` 实例。
2. **`loadRefs`**: 获取 `github.com/someuser/somerepo` 仓库的所有引用。
3. **`Stat`**: 查找标签 `v1.2.3` 对应的提交信息。
4. **`ReadZip`**: 下载 `v1.2.3` 对应的代码压缩包。
5. **其他校验和缓存操作**:  确保模块的完整性和一致性。

**命令行参数的具体处理:**

这段代码本身不直接处理用户输入的命令行参数。它是由 `cmd/go` 的其他部分调用，那些部分负责解析命令行参数。

但是，我们可以看到一些与命令行参数相关的逻辑：

- **`local` 参数 in `newGitRepo`**:  这个参数表明是否只进行本地查找，不进行远程获取。这可能对应于 `go` 命令的某些模式，例如在本地已经存在仓库的情况下。
- **`runGit` 函数执行的 Git 命令**:  这些命令可能受到 `go` 命令的命令行参数的影响，例如 `-mod=vendor` 会影响依赖的下载方式。

**涉及代码推理，带上假设的输入与输出:**

假设我们调用 `r.Stat(ctx, "v1.0.0")`，其中 `r` 是一个指向远程仓库 `https://github.com/myuser/myrepo` 的 `gitRepo` 实例。

**假设输入:**

- `ctx`:  一个 `context.Context` 实例。
- `rev`: 字符串 `"v1.0.0"` (一个标签)。
- `r.remoteURL`: 字符串 `"https://github.com/myuser/myrepo"`。
- 远程仓库 `https://github.com/myuser/myrepo` 存在标签 `v1.0.0`，指向提交 `abcdefg1234567890`。

**可能的输出 (取决于缓存状态和网络情况):**

1. **首次调用 (无缓存):**
   - `loadRefs` 会被调用，从远程仓库获取所有引用，包括 `refs/tags/v1.0.0`。
   - `statLocal` 可能会被调用，但由于本地仓库可能没有 `v1.0.0` 的信息，可能会失败。
   - `runGit` 可能会被调用执行 `git fetch --depth=1 origin refs/tags/v1.0.0:refs/tags/v1.0.0` 来获取标签 `v1.0.0` 的信息。
   - `statLocal` 再次被调用，此时本地仓库已经包含了 `v1.0.0` 的信息。
   - `Stat` 方法返回一个 `RevInfo` 结构体，包含以下信息 (部分):
     ```go
     &RevInfo{
         Origin: &Origin{
             VCS:  "git",
             URL:  "https://github.com/myuser/myrepo",
             Hash: "abcdefg1234567890",
             Ref:  "refs/tags/v1.0.0",
         },
         Name:    "abcdefg1234567890",
         Short:   "abcdefg",
         Time:    /* 提交时间 */,
         Version: "v1.0.0",
         Tags:    []string{"v1.0.0"},
     }
     ```

2. **后续调用 (有缓存):**
   - `Stat` 方法会先检查缓存 `r.statCache`。
   - 如果找到了键为 `"v1.0.0"` 的缓存项，则直接返回缓存的结果，避免重复的网络请求和 Git 命令执行。

**使用者易犯错的点:**

1. **依赖私有仓库但未配置凭据:** 如果尝试 `go get` 或 `go mod download` 私有 Git 仓库的模块，但没有配置 Git 凭据 (例如通过 `git config` 或 SSH keys)，则 `loadRefs` 可能会失败，并提示类似 "fatal: could not read Username for 'https://github.com': No such device or address" 的错误。

   **示例错误消息:**
   ```
   go: github.com/myuser/myprivaterepo@v1.0.0: reading github.com/myuser/myprivaterepo/go.mod at revision v1.0.0: unrecognized import path "github.com/myuser/myprivaterepo": reading https://proxy.golang.org/github.com/myuser/myprivaterepo/@v/list: 404 Not Found
   	server response: not found: github.com/myuser/myprivaterepo@v1.0.0: invalid version: git fetch --unshallow -f origin refs/heads/*:refs/heads/* refs/tags/*:refs/tags/* in /Users/myuser/go/pkg/mod/cache/vcs/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx: exit status 128
   ```

2. **网络问题:**  由于需要与远程 Git 仓库通信，网络连接不稳定或 DNS 解析问题会导致模块下载失败。

3. **本地 Git 环境问题:** 如果本地没有安装 Git 或 Git 命令不可用，`runGit` 函数会报错。

4. **Git LFS (Large File Storage) 相关问题:**  如果仓库使用了 Git LFS 并且没有正确配置，下载包含 LFS 对象的文件可能会失败。虽然代码中考虑了 Git LFS (添加了命名 remote 的逻辑)，但用户仍然需要在本地配置 LFS。

5. **浅克隆导致的问题:**  `fetch --depth=1` 用于浅克隆，在某些情况下，如果后续操作需要完整的历史记录 (例如 `DescendsFrom` 在第一次尝试时)，可能会导致问题，代码中也看到了处理浅克隆的逻辑 (`fetch --unshallow`)。

总而言之，这段 `git.go` 代码是 `go` 模块系统与 Git 仓库交互的核心组件，负责获取、管理和校验 Git 仓库中的模块依赖。理解其功能有助于理解 `go` 命令如何处理 Git 仓库托管的依赖。

### 提示词
```
这是路径为go/src/cmd/go/internal/modfetch/codehost/git.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package codehost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cmd/go/internal/base"
	"cmd/go/internal/lockedfile"
	"cmd/go/internal/web"
	"cmd/internal/par"

	"golang.org/x/mod/semver"
)

// A notExistError wraps another error to retain its original text
// but makes it opaquely equivalent to fs.ErrNotExist.
type notExistError struct {
	err error
}

func (e notExistError) Error() string   { return e.err.Error() }
func (notExistError) Is(err error) bool { return err == fs.ErrNotExist }

const gitWorkDirType = "git3"

func newGitRepo(ctx context.Context, remote string, local bool) (Repo, error) {
	r := &gitRepo{remote: remote, local: local}
	if local {
		if strings.Contains(remote, "://") { // Local flag, but URL provided
			return nil, fmt.Errorf("git remote (%s) lookup disabled", remote)
		}
		info, err := os.Stat(remote)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%s exists but is not a directory", remote)
		}
		r.dir = remote
		r.mu.Path = r.dir + ".lock"
		return r, nil
	}
	// This is a remote path lookup.
	if !strings.Contains(remote, "://") { // No URL scheme, could be host:path
		if strings.Contains(remote, ":") {
			return nil, fmt.Errorf("git remote (%s) must not be local directory (use URL syntax not host:path syntax)", remote)
		}
		return nil, fmt.Errorf("git remote (%s) must not be local directory", remote)
	}
	var err error
	r.dir, r.mu.Path, err = WorkDir(ctx, gitWorkDirType, r.remote)
	if err != nil {
		return nil, err
	}

	unlock, err := r.mu.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	if _, err := os.Stat(filepath.Join(r.dir, "objects")); err != nil {
		if _, err := Run(ctx, r.dir, "git", "init", "--bare"); err != nil {
			os.RemoveAll(r.dir)
			return nil, err
		}
		// We could just say git fetch https://whatever later,
		// but this lets us say git fetch origin instead, which
		// is a little nicer. More importantly, using a named remote
		// avoids a problem with Git LFS. See golang.org/issue/25605.
		if _, err := r.runGit(ctx, "git", "remote", "add", "origin", "--", r.remote); err != nil {
			os.RemoveAll(r.dir)
			return nil, err
		}
		if runtime.GOOS == "windows" {
			// Git for Windows by default does not support paths longer than
			// MAX_PATH (260 characters) because that may interfere with navigation
			// in some Windows programs. However, cmd/go should be able to handle
			// long paths just fine, and we expect people to use 'go clean' to
			// manipulate the module cache, so it should be harmless to set here,
			// and in some cases may be necessary in order to download modules with
			// long branch names.
			//
			// See https://github.com/git-for-windows/git/wiki/Git-cannot-create-a-file-or-directory-with-a-long-path.
			if _, err := r.runGit(ctx, "git", "config", "core.longpaths", "true"); err != nil {
				os.RemoveAll(r.dir)
				return nil, err
			}
		}
	}
	r.remoteURL = r.remote
	r.remote = "origin"
	return r, nil
}

type gitRepo struct {
	ctx context.Context

	remote, remoteURL string
	local             bool // local only lookups; no remote fetches
	dir               string

	mu lockedfile.Mutex // protects fetchLevel and git repo state

	fetchLevel int

	statCache par.ErrCache[string, *RevInfo]

	refsOnce sync.Once
	// refs maps branch and tag refs (e.g., "HEAD", "refs/heads/master")
	// to commits (e.g., "37ffd2e798afde829a34e8955b716ab730b2a6d6")
	refs    map[string]string
	refsErr error

	localTagsOnce sync.Once
	localTags     sync.Map // map[string]bool
}

const (
	// How much have we fetched into the git repo (in this process)?
	fetchNone = iota // nothing yet
	fetchSome        // shallow fetches of individual hashes
	fetchAll         // "fetch -t origin": get all remote branches and tags
)

// loadLocalTags loads tag references from the local git cache
// into the map r.localTags.
func (r *gitRepo) loadLocalTags(ctx context.Context) {
	// The git protocol sends all known refs and ls-remote filters them on the client side,
	// so we might as well record both heads and tags in one shot.
	// Most of the time we only care about tags but sometimes we care about heads too.
	out, err := r.runGit(ctx, "git", "tag", "-l")
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(out), "\n") {
		if line != "" {
			r.localTags.Store(line, true)
		}
	}
}

func (r *gitRepo) CheckReuse(ctx context.Context, old *Origin, subdir string) error {
	if old == nil {
		return fmt.Errorf("missing origin")
	}
	if old.VCS != "git" || old.URL != r.remoteURL {
		return fmt.Errorf("origin moved from %v %q to %v %q", old.VCS, old.URL, "git", r.remoteURL)
	}
	if old.Subdir != subdir {
		return fmt.Errorf("origin moved from %v %q %q to %v %q %q", old.VCS, old.URL, old.Subdir, "git", r.remoteURL, subdir)
	}

	// Note: Can have Hash with no Ref and no TagSum and no RepoSum,
	// meaning the Hash simply has to remain in the repo.
	// In that case we assume it does in the absence of any real way to check.
	// But if neither Hash nor TagSum is present, we have nothing to check,
	// which we take to mean we didn't record enough information to be sure.
	if old.Hash == "" && old.TagSum == "" && old.RepoSum == "" {
		return fmt.Errorf("non-specific origin")
	}

	r.loadRefs(ctx)
	if r.refsErr != nil {
		return r.refsErr
	}

	if old.Ref != "" {
		hash, ok := r.refs[old.Ref]
		if !ok {
			return fmt.Errorf("ref %q deleted", old.Ref)
		}
		if hash != old.Hash {
			return fmt.Errorf("ref %q moved from %s to %s", old.Ref, old.Hash, hash)
		}
	}
	if old.TagSum != "" {
		tags, err := r.Tags(ctx, old.TagPrefix)
		if err != nil {
			return err
		}
		if tags.Origin.TagSum != old.TagSum {
			return fmt.Errorf("tags changed")
		}
	}
	if old.RepoSum != "" {
		if r.repoSum(r.refs) != old.RepoSum {
			return fmt.Errorf("refs changed")
		}
	}
	return nil
}

// loadRefs loads heads and tags references from the remote into the map r.refs.
// The result is cached in memory.
func (r *gitRepo) loadRefs(ctx context.Context) (map[string]string, error) {
	if r.local { // Return results from the cache if local only.
		// In the future, we could consider loading r.refs using local git commands
		// if desired.
		return nil, nil
	}
	r.refsOnce.Do(func() {
		// The git protocol sends all known refs and ls-remote filters them on the client side,
		// so we might as well record both heads and tags in one shot.
		// Most of the time we only care about tags but sometimes we care about heads too.
		release, err := base.AcquireNet()
		if err != nil {
			r.refsErr = err
			return
		}
		out, gitErr := r.runGit(ctx, "git", "ls-remote", "-q", r.remote)
		release()

		if gitErr != nil {
			if rerr, ok := gitErr.(*RunError); ok {
				if bytes.Contains(rerr.Stderr, []byte("fatal: could not read Username")) {
					rerr.HelpText = "Confirm the import path was entered correctly.\nIf this is a private repository, see https://golang.org/doc/faq#git_https for additional information."
				}
			}

			// If the remote URL doesn't exist at all, ideally we should treat the whole
			// repository as nonexistent by wrapping the error in a notExistError.
			// For HTTP and HTTPS, that's easy to detect: we'll try to fetch the URL
			// ourselves and see what code it serves.
			if u, err := url.Parse(r.remoteURL); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
				if _, err := web.GetBytes(u); errors.Is(err, fs.ErrNotExist) {
					gitErr = notExistError{gitErr}
				}
			}

			r.refsErr = gitErr
			return
		}

		refs := make(map[string]string)
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) != 2 {
				continue
			}
			if f[1] == "HEAD" || strings.HasPrefix(f[1], "refs/heads/") || strings.HasPrefix(f[1], "refs/tags/") {
				refs[f[1]] = f[0]
			}
		}
		for ref, hash := range refs {
			if k, found := strings.CutSuffix(ref, "^{}"); found { // record unwrapped annotated tag as value of tag
				refs[k] = hash
				delete(refs, ref)
			}
		}
		r.refs = refs
	})
	return r.refs, r.refsErr
}

func (r *gitRepo) Tags(ctx context.Context, prefix string) (*Tags, error) {
	refs, err := r.loadRefs(ctx)
	if err != nil {
		return nil, err
	}

	tags := &Tags{
		Origin: &Origin{
			VCS:       "git",
			URL:       r.remoteURL,
			TagPrefix: prefix,
		},
		List: []Tag{},
	}
	for ref, hash := range refs {
		if !strings.HasPrefix(ref, "refs/tags/") {
			continue
		}
		tag := ref[len("refs/tags/"):]
		if !strings.HasPrefix(tag, prefix) {
			continue
		}
		tags.List = append(tags.List, Tag{tag, hash})
	}
	sort.Slice(tags.List, func(i, j int) bool {
		return tags.List[i].Name < tags.List[j].Name
	})

	dir := prefix[:strings.LastIndex(prefix, "/")+1]
	h := sha256.New()
	for _, tag := range tags.List {
		if isOriginTag(strings.TrimPrefix(tag.Name, dir)) {
			fmt.Fprintf(h, "%q %s\n", tag.Name, tag.Hash)
		}
	}
	tags.Origin.TagSum = "t1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
	return tags, nil
}

// repoSum returns a checksum of the entire repo state,
// which can be checked (as Origin.RepoSum) to cache
// the absence of a specific module version.
// The caller must supply refs, the result of a successful r.loadRefs.
func (r *gitRepo) repoSum(refs map[string]string) string {
	list := make([]string, 0, len(refs))
	for ref := range refs {
		list = append(list, ref)
	}
	sort.Strings(list)
	h := sha256.New()
	for _, ref := range list {
		fmt.Fprintf(h, "%q %s\n", ref, refs[ref])
	}
	return "r1:" + base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// unknownRevisionInfo returns a RevInfo containing an Origin containing a RepoSum of refs,
// for use when returning an UnknownRevisionError.
func (r *gitRepo) unknownRevisionInfo(refs map[string]string) *RevInfo {
	return &RevInfo{
		Origin: &Origin{
			VCS:     "git",
			URL:     r.remoteURL,
			RepoSum: r.repoSum(refs),
		},
	}
}

func (r *gitRepo) Latest(ctx context.Context) (*RevInfo, error) {
	refs, err := r.loadRefs(ctx)
	if err != nil {
		return nil, err
	}
	if refs["HEAD"] == "" {
		return nil, ErrNoCommits
	}
	statInfo, err := r.Stat(ctx, refs["HEAD"])
	if err != nil {
		return nil, err
	}

	// Stat may return cached info, so make a copy to modify here.
	info := new(RevInfo)
	*info = *statInfo
	info.Origin = new(Origin)
	if statInfo.Origin != nil {
		*info.Origin = *statInfo.Origin
	}
	info.Origin.Ref = "HEAD"
	info.Origin.Hash = refs["HEAD"]

	return info, nil
}

// findRef finds some ref name for the given hash,
// for use when the server requires giving a ref instead of a hash.
// There may be multiple ref names for a given hash,
// in which case this returns some name - it doesn't matter which.
func (r *gitRepo) findRef(ctx context.Context, hash string) (ref string, ok bool) {
	refs, err := r.loadRefs(ctx)
	if err != nil {
		return "", false
	}
	for ref, h := range refs {
		if h == hash {
			return ref, true
		}
	}
	return "", false
}

// minHashDigits is the minimum number of digits to require
// before accepting a hex digit sequence as potentially identifying
// a specific commit in a git repo. (Of course, users can always
// specify more digits, and many will paste in all 40 digits,
// but many of git's commands default to printing short hashes
// as 7 digits.)
const minHashDigits = 7

// stat stats the given rev in the local repository,
// or else it fetches more info from the remote repository and tries again.
func (r *gitRepo) stat(ctx context.Context, rev string) (info *RevInfo, err error) {
	// Fast path: maybe rev is a hash we already have locally.
	didStatLocal := false
	if len(rev) >= minHashDigits && len(rev) <= 40 && AllHex(rev) {
		if info, err := r.statLocal(ctx, rev, rev); err == nil {
			return info, nil
		}
		didStatLocal = true
	}

	// Maybe rev is a tag we already have locally.
	// (Note that we're excluding branches, which can be stale.)
	r.localTagsOnce.Do(func() { r.loadLocalTags(ctx) })
	if _, ok := r.localTags.Load(rev); ok {
		return r.statLocal(ctx, rev, "refs/tags/"+rev)
	}

	// Maybe rev is the name of a tag or branch on the remote server.
	// Or maybe it's the prefix of a hash of a named ref.
	// Try to resolve to both a ref (git name) and full (40-hex-digit) commit hash.
	refs, err := r.loadRefs(ctx)
	if err != nil {
		return nil, err
	}
	// loadRefs may return an error if git fails, for example segfaults, or
	// could not load a private repo, but defer checking to the else block
	// below, in case we already have the rev in question in the local cache.
	var ref, hash string
	if refs["refs/tags/"+rev] != "" {
		ref = "refs/tags/" + rev
		hash = refs[ref]
		// Keep rev as is: tags are assumed not to change meaning.
	} else if refs["refs/heads/"+rev] != "" {
		ref = "refs/heads/" + rev
		hash = refs[ref]
		rev = hash // Replace rev, because meaning of refs/heads/foo can change.
	} else if rev == "HEAD" && refs["HEAD"] != "" {
		ref = "HEAD"
		hash = refs[ref]
		rev = hash // Replace rev, because meaning of HEAD can change.
	} else if len(rev) >= minHashDigits && len(rev) <= 40 && AllHex(rev) {
		// At the least, we have a hash prefix we can look up after the fetch below.
		// Maybe we can map it to a full hash using the known refs.
		prefix := rev
		// Check whether rev is prefix of known ref hash.
		for k, h := range refs {
			if strings.HasPrefix(h, prefix) {
				if hash != "" && hash != h {
					// Hash is an ambiguous hash prefix.
					// More information will not change that.
					return nil, fmt.Errorf("ambiguous revision %s", rev)
				}
				if ref == "" || ref > k { // Break ties deterministically when multiple refs point at same hash.
					ref = k
				}
				rev = h
				hash = h
			}
		}
		if hash == "" && len(rev) == 40 { // Didn't find a ref, but rev is a full hash.
			hash = rev
		}
	} else {
		return r.unknownRevisionInfo(refs), &UnknownRevisionError{Rev: rev}
	}

	defer func() {
		if info != nil {
			info.Origin.Hash = info.Name
			// There's a ref = hash below; don't write that hash down as Origin.Ref.
			if ref != info.Origin.Hash {
				info.Origin.Ref = ref
			}
		}
	}()

	// Protect r.fetchLevel and the "fetch more and more" sequence.
	unlock, err := r.mu.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	// Perhaps r.localTags did not have the ref when we loaded local tags,
	// but we've since done fetches that pulled down the hash we need
	// (or already have the hash we need, just without its tag).
	// Either way, try a local stat before falling back to network I/O.
	if !didStatLocal {
		if info, err := r.statLocal(ctx, rev, hash); err == nil {
			tag, fromTag := strings.CutPrefix(ref, "refs/tags/")
			if fromTag && !slices.Contains(info.Tags, tag) {
				// The local repo includes the commit hash we want, but it is missing
				// the corresponding tag. Add that tag and try again.
				_, err := r.runGit(ctx, "git", "tag", tag, hash)
				if err != nil {
					return nil, err
				}
				r.localTags.Store(tag, true)
				return r.statLocal(ctx, rev, ref)
			}
			return info, err
		}
	}

	if r.local { // at this point, we have determined that we need to fetch rev, fail early if local only mode.
		return nil, fmt.Errorf("revision does not exist locally: %s", rev)
	}

	// If we know a specific commit we need and its ref, fetch it.
	// We do NOT fetch arbitrary hashes (when we don't know the ref)
	// because we want to avoid ever importing a commit that isn't
	// reachable from refs/tags/* or refs/heads/* or HEAD.
	// Both Gerrit and GitHub expose every CL/PR as a named ref,
	// and we don't want those commits masquerading as being real
	// pseudo-versions in the main repo.
	if r.fetchLevel <= fetchSome && ref != "" && hash != "" {
		r.fetchLevel = fetchSome
		var refspec string
		if ref == "HEAD" {
			// Fetch the hash but give it a local name (refs/dummy),
			// because that triggers the fetch behavior of creating any
			// other known remote tags for the hash. We never use
			// refs/dummy (it's not refs/tags/dummy) and it will be
			// overwritten in the next command, and that's fine.
			ref = hash
			refspec = hash + ":refs/dummy"
		} else {
			// If we do know the ref name, save the mapping locally
			// so that (if it is a tag) it can show up in localTags
			// on a future call. Also, some servers refuse to allow
			// full hashes in ref specs, so prefer a ref name if known.
			refspec = ref + ":" + ref
		}

		release, err := base.AcquireNet()
		if err != nil {
			return nil, err
		}
		// We explicitly set protocol.version=2 for this command to work around
		// an apparent Git bug introduced in Git 2.21 (commit 61c771),
		// which causes the handler for protocol version 1 to sometimes miss
		// tags that point to the requested commit (see https://go.dev/issue/56881).
		_, err = r.runGit(ctx, "git", "-c", "protocol.version=2", "fetch", "-f", "--depth=1", r.remote, refspec)
		release()

		if err == nil {
			return r.statLocal(ctx, rev, ref)
		}
		// Don't try to be smart about parsing the error.
		// It's too complex and varies too much by git version.
		// No matter what went wrong, fall back to a complete fetch.
	}

	// Last resort.
	// Fetch all heads and tags and hope the hash we want is in the history.
	if err := r.fetchRefsLocked(ctx); err != nil {
		return nil, err
	}

	return r.statLocal(ctx, rev, rev)
}

// fetchRefsLocked fetches all heads and tags from the origin, along with the
// ancestors of those commits.
//
// We only fetch heads and tags, not arbitrary other commits: we don't want to
// pull in off-branch commits (such as rejected GitHub pull requests) that the
// server may be willing to provide. (See the comments within the stat method
// for more detail.)
//
// fetchRefsLocked requires that r.mu remain locked for the duration of the call.
func (r *gitRepo) fetchRefsLocked(ctx context.Context) error {
	if r.local {
		panic("go: fetchRefsLocked called in local only mode.")
	}
	if r.fetchLevel < fetchAll {
		// NOTE: To work around a bug affecting Git clients up to at least 2.23.0
		// (2019-08-16), we must first expand the set of local refs, and only then
		// unshallow the repository as a separate fetch operation. (See
		// golang.org/issue/34266 and
		// https://github.com/git/git/blob/4c86140027f4a0d2caaa3ab4bd8bfc5ce3c11c8a/transport.c#L1303-L1309.)

		release, err := base.AcquireNet()
		if err != nil {
			return err
		}
		defer release()

		if _, err := r.runGit(ctx, "git", "fetch", "-f", r.remote, "refs/heads/*:refs/heads/*", "refs/tags/*:refs/tags/*"); err != nil {
			return err
		}

		if _, err := os.Stat(filepath.Join(r.dir, "shallow")); err == nil {
			if _, err := r.runGit(ctx, "git", "fetch", "--unshallow", "-f", r.remote); err != nil {
				return err
			}
		}

		r.fetchLevel = fetchAll
	}
	return nil
}

// statLocal returns a new RevInfo describing rev in the local git repository.
// It uses version as info.Version.
func (r *gitRepo) statLocal(ctx context.Context, version, rev string) (*RevInfo, error) {
	out, err := r.runGit(ctx, "git", "-c", "log.showsignature=false", "log", "--no-decorate", "-n1", "--format=format:%H %ct %D", rev, "--")
	if err != nil {
		// Return info with Origin.RepoSum if possible to allow caching of negative lookup.
		var info *RevInfo
		if refs, err := r.loadRefs(ctx); err == nil {
			info = r.unknownRevisionInfo(refs)
		}
		return info, &UnknownRevisionError{Rev: rev}
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return nil, fmt.Errorf("unexpected response from git log: %q", out)
	}
	hash := f[0]
	if strings.HasPrefix(hash, version) {
		version = hash // extend to full hash
	}
	t, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid time from git log: %q", out)
	}

	info := &RevInfo{
		Origin: &Origin{
			VCS:  "git",
			URL:  r.remoteURL,
			Hash: hash,
		},
		Name:    hash,
		Short:   ShortenSHA1(hash),
		Time:    time.Unix(t, 0).UTC(),
		Version: hash,
	}
	if !strings.HasPrefix(hash, rev) {
		info.Origin.Ref = rev
	}

	// Add tags. Output looks like:
	//	ede458df7cd0fdca520df19a33158086a8a68e81 1523994202 HEAD -> master, tag: v1.2.4-annotated, tag: v1.2.3, origin/master, origin/HEAD
	for i := 2; i < len(f); i++ {
		if f[i] == "tag:" {
			i++
			if i < len(f) {
				info.Tags = append(info.Tags, strings.TrimSuffix(f[i], ","))
			}
		}
	}
	sort.Strings(info.Tags)

	// Used hash as info.Version above.
	// Use caller's suggested version if it appears in the tag list
	// (filters out branch names, HEAD).
	for _, tag := range info.Tags {
		if version == tag {
			info.Version = version
		}
	}

	return info, nil
}

func (r *gitRepo) Stat(ctx context.Context, rev string) (*RevInfo, error) {
	if rev == "latest" {
		return r.Latest(ctx)
	}
	return r.statCache.Do(rev, func() (*RevInfo, error) {
		return r.stat(ctx, rev)
	})
}

func (r *gitRepo) ReadFile(ctx context.Context, rev, file string, maxSize int64) ([]byte, error) {
	// TODO: Could use git cat-file --batch.
	info, err := r.Stat(ctx, rev) // download rev into local git repo
	if err != nil {
		return nil, err
	}
	out, err := r.runGit(ctx, "git", "cat-file", "blob", info.Name+":"+file)
	if err != nil {
		return nil, fs.ErrNotExist
	}
	return out, nil
}

func (r *gitRepo) RecentTag(ctx context.Context, rev, prefix string, allowed func(tag string) bool) (tag string, err error) {
	info, err := r.Stat(ctx, rev)
	if err != nil {
		return "", err
	}
	rev = info.Name // expand hash prefixes

	// describe sets tag and err using 'git for-each-ref' and reports whether the
	// result is definitive.
	describe := func() (definitive bool) {
		var out []byte
		out, err = r.runGit(ctx, "git", "for-each-ref", "--format", "%(refname)", "refs/tags", "--merged", rev)
		if err != nil {
			return true
		}

		// prefixed tags aren't valid semver tags so compare without prefix, but only tags with correct prefix
		var highest string
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			// git do support lstrip in for-each-ref format, but it was added in v2.13.0. Stripping here
			// instead gives support for git v2.7.0.
			if !strings.HasPrefix(line, "refs/tags/") {
				continue
			}
			line = line[len("refs/tags/"):]

			if !strings.HasPrefix(line, prefix) {
				continue
			}
			if !allowed(line) {
				continue
			}

			semtag := line[len(prefix):]
			if semver.Compare(semtag, highest) > 0 {
				highest = semtag
			}
		}

		if highest != "" {
			tag = prefix + highest
		}

		return tag != "" && !AllHex(tag)
	}

	if describe() {
		return tag, err
	}

	// Git didn't find a version tag preceding the requested rev.
	// See whether any plausible tag exists.
	tags, err := r.Tags(ctx, prefix+"v")
	if err != nil {
		return "", err
	}
	if len(tags.List) == 0 {
		return "", nil
	}

	if r.local { // at this point, we have determined that we need to fetch rev, fail early if local only mode.
		return "", fmt.Errorf("revision does not exist locally: %s", rev)
	}
	// There are plausible tags, but we don't know if rev is a descendent of any of them.
	// Fetch the history to find out.

	unlock, err := r.mu.Lock()
	if err != nil {
		return "", err
	}
	defer unlock()

	if err := r.fetchRefsLocked(ctx); err != nil {
		return "", err
	}

	// If we've reached this point, we have all of the commits that are reachable
	// from all heads and tags.
	//
	// The only refs we should be missing are those that are no longer reachable
	// (or never were reachable) from any branch or tag, including the master
	// branch, and we don't want to resolve them anyway (they're probably
	// unreachable for a reason).
	//
	// Try one last time in case some other goroutine fetched rev while we were
	// waiting on the lock.
	describe()
	return tag, err
}

func (r *gitRepo) DescendsFrom(ctx context.Context, rev, tag string) (bool, error) {
	// The "--is-ancestor" flag was added to "git merge-base" in version 1.8.0, so
	// this won't work with Git 1.7.1. According to golang.org/issue/28550, cmd/go
	// already doesn't work with Git 1.7.1, so at least it's not a regression.
	//
	// git merge-base --is-ancestor exits with status 0 if rev is an ancestor, or
	// 1 if not.
	_, err := r.runGit(ctx, "git", "merge-base", "--is-ancestor", "--", tag, rev)

	// Git reports "is an ancestor" with exit code 0 and "not an ancestor" with
	// exit code 1.
	// Unfortunately, if we've already fetched rev with a shallow history, git
	// merge-base has been observed to report a false-negative, so don't stop yet
	// even if the exit code is 1!
	if err == nil {
		return true, nil
	}

	// See whether the tag and rev even exist.
	tags, err := r.Tags(ctx, tag)
	if err != nil {
		return false, err
	}
	if len(tags.List) == 0 {
		return false, nil
	}

	// NOTE: r.stat is very careful not to fetch commits that we shouldn't know
	// about, like rejected GitHub pull requests, so don't try to short-circuit
	// that here.
	if _, err = r.stat(ctx, rev); err != nil {
		return false, err
	}

	if r.local { // at this point, we have determined that we need to fetch rev, fail early if local only mode.
		return false, fmt.Errorf("revision does not exist locally: %s", rev)
	}

	// Now fetch history so that git can search for a path.
	unlock, err := r.mu.Lock()
	if err != nil {
		return false, err
	}
	defer unlock()

	if r.fetchLevel < fetchAll {
		// Fetch the complete history for all refs and heads. It would be more
		// efficient to only fetch the history from rev to tag, but that's much more
		// complicated, and any kind of shallow fetch is fairly likely to trigger
		// bugs in JGit servers and/or the go command anyway.
		if err := r.fetchRefsLocked(ctx); err != nil {
			return false, err
		}
	}

	_, err = r.runGit(ctx, "git", "merge-base", "--is-ancestor", "--", tag, rev)
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(*RunError).Err.(*exec.ExitError); ok && ee.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func (r *gitRepo) ReadZip(ctx context.Context, rev, subdir string, maxSize int64) (zip io.ReadCloser, err error) {
	// TODO: Use maxSize or drop it.
	args := []string{}
	if subdir != "" {
		args = append(args, "--", subdir)
	}
	info, err := r.Stat(ctx, rev) // download rev into local git repo
	if err != nil {
		return nil, err
	}

	unlock, err := r.mu.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	if err := ensureGitAttributes(r.dir); err != nil {
		return nil, err
	}

	// Incredibly, git produces different archives depending on whether
	// it is running on a Windows system or not, in an attempt to normalize
	// text file line endings. Setting -c core.autocrlf=input means only
	// translate files on the way into the repo, not on the way out (archive).
	// The -c core.eol=lf should be unnecessary but set it anyway.
	archive, err := r.runGit(ctx, "git", "-c", "core.autocrlf=input", "-c", "core.eol=lf", "archive", "--format=zip", "--prefix=prefix/", info.Name, args)
	if err != nil {
		if bytes.Contains(err.(*RunError).Stderr, []byte("did not match any files")) {
			return nil, fs.ErrNotExist
		}
		return nil, err
	}

	return io.NopCloser(bytes.NewReader(archive)), nil
}

// ensureGitAttributes makes sure export-subst and export-ignore features are
// disabled for this repo. This is intended to be run prior to running git
// archive so that zip files are generated that produce consistent ziphashes
// for a given revision, independent of variables such as git version and the
// size of the repo.
//
// See: https://github.com/golang/go/issues/27153
func ensureGitAttributes(repoDir string) (err error) {
	const attr = "\n* -export-subst -export-ignore\n"

	d := repoDir + "/info"
	p := d + "/attributes"

	if err := os.MkdirAll(d, 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := f.Close()
		if closeErr != nil {
			err = closeErr
		}
	}()

	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	if !bytes.HasSuffix(b, []byte(attr)) {
		_, err := f.WriteString(attr)
		return err
	}

	return nil
}

func (r *gitRepo) runGit(ctx context.Context, cmdline ...any) ([]byte, error) {
	args := RunArgs{cmdline: cmdline, dir: r.dir, local: r.local}
	if !r.local {
		// Manually supply GIT_DIR so Git works with safe.bareRepository=explicit set.
		// This is necessary only for remote repositories as they are initialized with git init --bare.
		args.env = []string{"GIT_DIR=" + r.dir}
	}
	return RunWithArgs(ctx, args)
}
```