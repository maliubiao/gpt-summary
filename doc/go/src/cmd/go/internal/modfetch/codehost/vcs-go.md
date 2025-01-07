Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionalities of the code, potential Go feature implementations, code examples (with assumptions), command-line argument handling, and common pitfalls.

2. **Initial Scan for Core Concepts:**  Read through the code looking for keywords, data structures, and function names that hint at the purpose. I see:
    * `package codehost`: Suggests dealing with remote code repositories.
    * `VCSError`:  Clearly an error type related to version control.
    * `Repo` interface (though not shown, it's used as a return type):  Indicates an abstraction for a repository.
    * `vcsRepo`, `newVCSRepo`: Concrete implementation of the `Repo` interface, suggesting a common structure for different VCS.
    * `vcsCmd`, `vcsCmds`:  A structure to hold commands for various VCS (git, hg, svn, bzr, fossil) and a map to access them.
    * Functions like `Tags`, `Stat`, `ReadFile`, `ReadZip`, `Latest`: These are typical operations on a version-controlled repository.
    * `par.ErrCache`:  Indicates caching of repository objects.
    * `lockedfile.Mutex`:  Concurrency control for repository operations.

3. **Identify Key Functionalities (First Pass):** Based on the initial scan, I can infer these core functionalities:
    * **Abstraction over VCS:**  The code aims to provide a common interface for interacting with different version control systems.
    * **Repository Management:** Creating, accessing, and managing local representations of remote repositories.
    * **Metadata Retrieval:**  Fetching tags, branches, and commit information (`Stat`).
    * **Content Retrieval:** Reading files and directories (as zip archives) from specific revisions.
    * **Caching:**  Improving performance by caching `Repo` instances.
    * **Concurrency Control:** Ensuring safe access to repository data.

4. **Deep Dive into `vcsRepo` and `newVCSRepo`:** These are central to the implementation.
    * `newVCSRepo`:  Handles the creation of a `vcsRepo`. Notice the logic for local vs. remote repositories, the `vcsCmds` lookup, and the initialization steps (cloning for remote repos). This is where the different VCS are handled.
    * `vcsRepo`: Contains the state for a repository (remote URL, command set, local directory, cached tags/branches, etc.).

5. **Analyze Individual `vcsCmd` Definitions:** Examine the commands defined for each VCS (git, hg, svn, etc.). This confirms the code's interaction with the actual VCS tools. Notice the differences in how each VCS handles commands like listing tags or reading files.

6. **Connect Functionalities to Go Features:**
    * **Interfaces:** The `Repo` interface (implicitly used) is a key Go feature for abstraction.
    * **Structs:** `VCSError`, `vcsRepo`, `vcsCmd`, `RevInfo`, `Tags`, etc., represent data structures.
    * **Maps:** `vcsCmds` uses a map to associate VCS names with their commands.
    * **Functions as Values:**  The `init`, `tags`, `readFile`, etc., fields in `vcsCmd` are functions.
    * **Concurrency:** `sync.Once` for lazy initialization, `lockedfile.Mutex` for thread safety, `par.ErrCache` for concurrent access to the cache.
    * **Error Handling:**  The `VCSError` type and the consistent checking for errors.
    * **Regular Expressions:** `lazyregexp` is used for parsing output from VCS commands.
    * **Context:**  The use of `context.Context` for managing timeouts and cancellations.

7. **Construct Code Examples:** Choose a key functionality (like getting tags) and demonstrate its usage. This requires making assumptions about how the `Repo` interface is defined. Focus on showing how the `NewRepo` function is likely used and how the `Tags` method is called.

8. **Identify Potential Command-Line Arguments:** Look for code that interacts with the `os` package or suggests external command execution. The `vcsCmd` struct and the `Run` function strongly indicate command-line interaction. Think about what arguments a `go` command dealing with modules might take (e.g., specifying the VCS type or repository URL, though these might be inferred).

9. **Pinpoint Common Pitfalls:**  Think about how users might misuse the provided functionality or encounter common errors. Consider:
    * **Incorrect VCS or Remote URL:**  The `NewRepo` function checks for these.
    * **Local Repository Issues:** Permissions, not being a directory.
    * **Network Issues:**  The code explicitly acquires network access.
    * **Assumptions about Local State:** The caching might lead to unexpected behavior if the local repository isn't up-to-date.
    * **Concurrency Issues (if the locking isn't understood):** Although the code handles it, misusing the `Repo` might lead to problems.

10. **Refine and Organize:** Review the generated points and organize them logically. Ensure the explanations are clear and concise. Add details where necessary (e.g., explaining the purpose of `VCSError`). Make sure the code examples are valid Go syntax.

11. **Self-Correction/Review:** Read through the entire response. Does it accurately reflect the code's functionality? Are the examples clear and correct? Are the assumptions reasonable?  Have I missed any important aspects? For instance, initially, I might have overlooked the `par.ErrCache` and its significance in caching. A review step would help catch this. Also, consider the "TODO" comment in the code –  it provides insight into potential future changes and the current error handling strategy.

This iterative process of scanning, analyzing, connecting concepts, and refining allows for a comprehensive understanding of the code snippet and the ability to address all parts of the request.
这段代码是 Go 语言 `cmd/go` 工具中负责与版本控制系统 (VCS) 交互的一部分，具体来说，它提供了与不同 VCS（如 Git, Mercurial, Subversion, Bazaar, Fossil）进行操作的抽象和实现。

**它的主要功能包括:**

1. **VCS 仓库的抽象:** 定义了 `Repo` 接口（虽然这段代码中没有明确展示，但可以推断出来）以及 `vcsRepo` 结构体作为其实现，用于表示一个 VCS 仓库。这层抽象使得 `cmd/go` 可以以统一的方式处理不同的 VCS。

2. **VCS 命令的封装:**  定义了 `vcsCmd` 结构体，其中包含了执行不同 VCS 操作所需的命令和正则表达式。例如，获取标签列表、获取提交信息、读取文件等。`vcsCmds` 变量是一个 map，存储了不同 VCS 对应的 `vcsCmd` 实例。

3. **仓库的创建和管理:**  `NewRepo` 函数负责根据给定的 VCS 类型和远程地址创建一个 `Repo` 实例。它会利用 `vcsRepoCache` 来缓存已创建的仓库实例，避免重复创建。对于本地仓库，它会进行简单的目录检查。对于远程仓库，它会在工作目录中执行 VCS 的初始化命令 (如 `git clone`)。

4. **获取仓库信息:**
   - `Tags`:  获取仓库的标签列表。
   - `Stat`: 获取指定修订版本 (commit/tag/branch) 的详细信息，例如哈希值、时间戳等。
   - `Latest`: 获取仓库最新提交的信息。

5. **读取仓库内容:**
   - `ReadFile`:  读取指定修订版本中特定文件的内容。
   - `ReadZip`:  读取指定修订版本中特定子目录的内容，并以 ZIP 格式返回。

6. **本地缓存管理:**  使用 `lockedfile.Mutex` 来保护对本地仓库的操作，避免并发冲突。使用工作目录来存储克隆的远程仓库。

7. **错误处理:** 定义了 `VCSError` 类型，用于表示在与 VCS 交互时发生的已知错误，例如仓库不存在。

**它是什么 go 语言功能的实现？**

这段代码是 Go 模块 (Go Modules) 功能中 **模块下载和版本控制** 的核心实现之一。当 `go get` 或其他 `go` 命令需要下载一个模块时，它会根据模块路径中的 VCS 信息，使用这段代码来与相应的 VCS 仓库进行交互，获取模块的代码。

**Go 代码举例说明:**

假设我们要获取 `golang.org/x/text` 模块的最新版本。`cmd/go` 会根据其导入路径判断需要使用 Git 进行下载。

```go
package main

import (
	"context"
	"fmt"
	"log"

	"cmd/go/internal/modfetch/codehost"
)

func main() {
	ctx := context.Background()
	repo, err := codehost.NewRepo(ctx, "git", "https://go.googlesource.com/text", false)
	if err != nil {
		log.Fatal(err)
	}

	latest, err := repo.Latest(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Latest revision of golang.org/x/text: %s at %s\n", latest.Name, latest.Time)

	// 获取指定文件的内容
	content, err := repo.ReadFile(ctx, latest.Name, "README.md", 1024*1024)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("\nREADME.md content (partial):\n", string(content[:200])) // 打印部分内容

	// 获取特定标签的提交信息
	stat, err := repo.Stat(ctx, "v0.3.7")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nInformation for tag v0.3.7: %s at %s\n", stat.Name, stat.Time)

	// 获取代码的 zip 包
	zipReader, err := repo.ReadZip(ctx, latest.Name, "language", 1024*1024)
	if err != nil {
		log.Fatal(err)
	}
	defer zipReader.Close()
	fmt.Println("\nSuccessfully retrieved language directory as zip.")
	// 可以进一步处理 zipReader
}
```

**假设的输入与输出:**

假设在执行上述代码时，网络连接正常，并且 `https://go.googlesource.com/text` 是一个有效的 Git 仓库。

**可能的输出:**

```
Latest revision of golang.org/x/text: <commit_hash> at <timestamp>
<BLANKLINE>
README.md content (partial):
# text

This repository holds packages for working with text.

See the [top-level README](https://go.googlesource.com/go/+/master/src/go.mod)
for general information.

## Sub-repositories

The text package is organized into the following sub-repositories:

*  [bidi](/bidi): Implements the Unicode Bidirectional Algorithm.
*  [collate](/collate): Implements Unicode collation (sorting).
*  [currency](/currency): Implements currency formatting and parsing.
*  [encoding](/encoding): Implements encoding and decoding of text in various encodings.
*  [feature](/feature): Supports the definition of language features and their variation.
*  [internal/cat](/internal/cat): Internal support for Unicode categories.
*  [internal/export](/internal/export): Internal support for exporting data.
*  [internal/language](/internal/language): Internal support for language tags.
*  [internal/tag](/internal/tag): Internal support for language tags.
*  [internal/triegen](/internal/triegen): Generates trie data structures.
*  [language](/language): Implements BCP 47 language tags and associated functionality.
*  [message](/message): Implements formatted message printing with support for pluralization and localized messages.
*  [number](/number): Implements number formatting and parsing.
*  [secure/bidirule](/secure/bidirule): Implements the proposed Unicode Standard Annex #39, Unicode Security Mechanisms.
*  [transform](/transform): Implements text transformation.
*  [unicode/cldr](/unicode/cldr): Data derived from the Unicode Consortium's CLDR project.
*  [unicode/norm](/unicode/norm): Implements the Unicode Normalization Forms.
*  [width](/width): Implements Unicode width properties.
<BLANKLINE>
Information for tag v0.3.7: <commit_hash_for_v0.3.7> at <timestamp_for_v0.3.7>
<BLANKLINE>
Successfully retrieved language directory as zip.
```

**涉及的命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它被 `cmd/go` 工具的其他部分调用，而 `cmd/go` 工具会解析命令行参数。例如：

- 当执行 `go get golang.org/x/text` 时，`go get` 命令会解析 `golang.org/x/text` 这个路径。
- `cmd/go` 的模块下载逻辑会根据这个路径判断需要使用 Git，并提取出仓库的远程地址 `https://go.googlesource.com/text`.
- 然后，`NewRepo` 函数会被调用，传入 VCS 类型 "git" 和远程地址。

**使用者易犯错的点:**

1. **错误的 VCS 类型或远程地址:** 如果提供的 VCS 类型与实际仓库不符，或者远程地址错误，`NewRepo` 函数会返回错误。例如，尝试将一个 Mercurial 仓库当作 Git 仓库处理。

   ```go
   _, err := codehost.NewRepo(ctx, "git", "https://hg.example.com/myrepo", false)
   if err != nil {
       fmt.Println("Error:", err) // 可能输出: Error: unknown vcs: git https://hg.example.com/myrepo
   }
   ```

2. **本地仓库路径问题:**  如果尝试创建一个本地仓库的 `Repo`，但提供的路径不是一个目录，或者不是一个有效的 VCS 仓库，也会出错。

   ```go
   _, err := codehost.NewRepo(ctx, "git", "/path/to/nonexistent/dir", true)
   if err != nil {
       fmt.Println("Error:", err)
   }

   _, err = codehost.NewRepo(ctx, "git", "/path/to/a/file", true)
   if err != nil {
       fmt.Println("Error:", err) // 可能输出: Error: /path/to/a/file exists but is not a directory
   }
   ```

3. **网络问题:**  对于远程仓库，如果网络连接不可用，或者无法访问指定的远程地址，相关的操作（如 `Latest`, `ReadFile`, `ReadZip`) 会失败。 这不是这段代码直接控制的，但用户在使用时会遇到。

4. **对 `latest` 的理解:**  `latest` 通常指的是版本控制系统的默认分支的最新提交（例如 Git 的 `HEAD`, Mercurial 的 `tip`）。用户可能会错误地认为 `latest` 总是指向最新的已发布版本 (tag)。

5. **并发安全问题（如果直接使用 `vcsRepo`）:**  虽然 `vcsRepo` 内部使用了 `lockedfile.Mutex` 进行保护，但如果使用者不了解其机制，直接并发地操作同一个 `vcsRepo` 实例仍然可能导致问题。不过，在 `cmd/go` 的上下文中，这种直接操作通常是被封装起来的。

总而言之，这段代码是 Go 模块功能中与版本控制系统交互的关键部分，它提供了抽象和实现，使得 `cmd/go` 可以方便地从不同的 VCS 仓库下载和管理模块代码。

Prompt: 
```
这是路径为go/src/cmd/go/internal/modfetch/codehost/vcs.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"context"
	"errors"
	"fmt"
	"internal/lazyregexp"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cmd/go/internal/base"
	"cmd/go/internal/lockedfile"
	"cmd/go/internal/str"
	"cmd/internal/par"
)

// A VCSError indicates an error using a version control system.
// The implication of a VCSError is that we know definitively where
// to get the code, but we can't access it due to the error.
// The caller should report this error instead of continuing to probe
// other possible module paths.
//
// TODO(golang.org/issue/31730): See if we can invert this. (Return a
// distinguished error for “repo not found” and treat everything else
// as terminal.)
type VCSError struct {
	Err error
}

func (e *VCSError) Error() string { return e.Err.Error() }

func (e *VCSError) Unwrap() error { return e.Err }

func vcsErrorf(format string, a ...any) error {
	return &VCSError{Err: fmt.Errorf(format, a...)}
}

type vcsCacheKey struct {
	vcs    string
	remote string
	local  bool
}

func NewRepo(ctx context.Context, vcs, remote string, local bool) (Repo, error) {
	return vcsRepoCache.Do(vcsCacheKey{vcs, remote, local}, func() (Repo, error) {
		repo, err := newVCSRepo(ctx, vcs, remote, local)
		if err != nil {
			return nil, &VCSError{err}
		}
		return repo, nil
	})
}

var vcsRepoCache par.ErrCache[vcsCacheKey, Repo]

type vcsRepo struct {
	mu lockedfile.Mutex // protects all commands, so we don't have to decide which are safe on a per-VCS basis

	remote string
	cmd    *vcsCmd
	dir    string
	local  bool

	tagsOnce sync.Once
	tags     map[string]bool

	branchesOnce sync.Once
	branches     map[string]bool

	fetchOnce sync.Once
	fetchErr  error
}

func newVCSRepo(ctx context.Context, vcs, remote string, local bool) (Repo, error) {
	if vcs == "git" {
		return newGitRepo(ctx, remote, local)
	}
	r := &vcsRepo{remote: remote, local: local}
	cmd := vcsCmds[vcs]
	if cmd == nil {
		return nil, fmt.Errorf("unknown vcs: %s %s", vcs, remote)
	}
	r.cmd = cmd
	if local {
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
	if !strings.Contains(remote, "://") {
		return nil, fmt.Errorf("invalid vcs remote: %s %s", vcs, remote)
	}
	var err error
	r.dir, r.mu.Path, err = WorkDir(ctx, vcsWorkDirType+vcs, r.remote)
	if err != nil {
		return nil, err
	}

	if cmd.init == nil {
		return r, nil
	}

	unlock, err := r.mu.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	if _, err := os.Stat(filepath.Join(r.dir, "."+vcs)); err != nil {
		release, err := base.AcquireNet()
		if err != nil {
			return nil, err
		}
		_, err = Run(ctx, r.dir, cmd.init(r.remote))
		release()

		if err != nil {
			os.RemoveAll(r.dir)
			return nil, err
		}
	}
	return r, nil
}

const vcsWorkDirType = "vcs1."

type vcsCmd struct {
	vcs           string                                                                              // vcs name "hg"
	init          func(remote string) []string                                                        // cmd to init repo to track remote
	tags          func(remote string) []string                                                        // cmd to list local tags
	tagRE         *lazyregexp.Regexp                                                                  // regexp to extract tag names from output of tags cmd
	branches      func(remote string) []string                                                        // cmd to list local branches
	branchRE      *lazyregexp.Regexp                                                                  // regexp to extract branch names from output of tags cmd
	badLocalRevRE *lazyregexp.Regexp                                                                  // regexp of names that must not be served out of local cache without doing fetch first
	statLocal     func(rev, remote string) []string                                                   // cmd to stat local rev
	parseStat     func(rev, out string) (*RevInfo, error)                                             // cmd to parse output of statLocal
	fetch         []string                                                                            // cmd to fetch everything from remote
	latest        string                                                                              // name of latest commit on remote (tip, HEAD, etc)
	readFile      func(rev, file, remote string) []string                                             // cmd to read rev's file
	readZip       func(rev, subdir, remote, target string) []string                                   // cmd to read rev's subdir as zip file
	doReadZip     func(ctx context.Context, dst io.Writer, workDir, rev, subdir, remote string) error // arbitrary function to read rev's subdir as zip file
}

var re = lazyregexp.New

var vcsCmds = map[string]*vcsCmd{
	"hg": {
		vcs: "hg",
		init: func(remote string) []string {
			return []string{"hg", "clone", "-U", "--", remote, "."}
		},
		tags: func(remote string) []string {
			return []string{"hg", "tags", "-q"}
		},
		tagRE: re(`(?m)^[^\n]+$`),
		branches: func(remote string) []string {
			return []string{"hg", "branches", "-c", "-q"}
		},
		branchRE:      re(`(?m)^[^\n]+$`),
		badLocalRevRE: re(`(?m)^(tip)$`),
		statLocal: func(rev, remote string) []string {
			return []string{"hg", "log", "-l1", "-r", rev, "--template", "{node} {date|hgdate} {tags}"}
		},
		parseStat: hgParseStat,
		fetch:     []string{"hg", "pull", "-f"},
		latest:    "tip",
		readFile: func(rev, file, remote string) []string {
			return []string{"hg", "cat", "-r", rev, file}
		},
		readZip: func(rev, subdir, remote, target string) []string {
			pattern := []string{}
			if subdir != "" {
				pattern = []string{"-I", subdir + "/**"}
			}
			return str.StringList("hg", "archive", "-t", "zip", "--no-decode", "-r", rev, "--prefix=prefix/", pattern, "--", target)
		},
	},

	"svn": {
		vcs:  "svn",
		init: nil, // no local checkout
		tags: func(remote string) []string {
			return []string{"svn", "list", "--", strings.TrimSuffix(remote, "/trunk") + "/tags"}
		},
		tagRE: re(`(?m)^(.*?)/?$`),
		statLocal: func(rev, remote string) []string {
			suffix := "@" + rev
			if rev == "latest" {
				suffix = ""
			}
			return []string{"svn", "log", "-l1", "--xml", "--", remote + suffix}
		},
		parseStat: svnParseStat,
		latest:    "latest",
		readFile: func(rev, file, remote string) []string {
			return []string{"svn", "cat", "--", remote + "/" + file + "@" + rev}
		},
		doReadZip: svnReadZip,
	},

	"bzr": {
		vcs: "bzr",
		init: func(remote string) []string {
			return []string{"bzr", "branch", "--use-existing-dir", "--", remote, "."}
		},
		fetch: []string{
			"bzr", "pull", "--overwrite-tags",
		},
		tags: func(remote string) []string {
			return []string{"bzr", "tags"}
		},
		tagRE:         re(`(?m)^\S+`),
		badLocalRevRE: re(`^revno:-`),
		statLocal: func(rev, remote string) []string {
			return []string{"bzr", "log", "-l1", "--long", "--show-ids", "-r", rev}
		},
		parseStat: bzrParseStat,
		latest:    "revno:-1",
		readFile: func(rev, file, remote string) []string {
			return []string{"bzr", "cat", "-r", rev, file}
		},
		readZip: func(rev, subdir, remote, target string) []string {
			extra := []string{}
			if subdir != "" {
				extra = []string{"./" + subdir}
			}
			return str.StringList("bzr", "export", "--format=zip", "-r", rev, "--root=prefix/", "--", target, extra)
		},
	},

	"fossil": {
		vcs: "fossil",
		init: func(remote string) []string {
			return []string{"fossil", "clone", "--", remote, ".fossil"}
		},
		fetch: []string{"fossil", "pull", "-R", ".fossil"},
		tags: func(remote string) []string {
			return []string{"fossil", "tag", "-R", ".fossil", "list"}
		},
		tagRE: re(`XXXTODO`),
		statLocal: func(rev, remote string) []string {
			return []string{"fossil", "info", "-R", ".fossil", rev}
		},
		parseStat: fossilParseStat,
		latest:    "trunk",
		readFile: func(rev, file, remote string) []string {
			return []string{"fossil", "cat", "-R", ".fossil", "-r", rev, file}
		},
		readZip: func(rev, subdir, remote, target string) []string {
			extra := []string{}
			if subdir != "" && !strings.ContainsAny(subdir, "*?[],") {
				extra = []string{"--include", subdir}
			}
			// Note that vcsRepo.ReadZip below rewrites this command
			// to run in a different directory, to work around a fossil bug.
			return str.StringList("fossil", "zip", "-R", ".fossil", "--name", "prefix", extra, "--", rev, target)
		},
	},
}

func (r *vcsRepo) loadTags(ctx context.Context) {
	out, err := Run(ctx, r.dir, r.cmd.tags(r.remote))
	if err != nil {
		return
	}

	// Run tag-listing command and extract tags.
	r.tags = make(map[string]bool)
	for _, tag := range r.cmd.tagRE.FindAllString(string(out), -1) {
		if r.cmd.badLocalRevRE != nil && r.cmd.badLocalRevRE.MatchString(tag) {
			continue
		}
		r.tags[tag] = true
	}
}

func (r *vcsRepo) loadBranches(ctx context.Context) {
	if r.cmd.branches == nil {
		return
	}

	out, err := Run(ctx, r.dir, r.cmd.branches(r.remote))
	if err != nil {
		return
	}

	r.branches = make(map[string]bool)
	for _, branch := range r.cmd.branchRE.FindAllString(string(out), -1) {
		if r.cmd.badLocalRevRE != nil && r.cmd.badLocalRevRE.MatchString(branch) {
			continue
		}
		r.branches[branch] = true
	}
}

func (r *vcsRepo) CheckReuse(ctx context.Context, old *Origin, subdir string) error {
	return fmt.Errorf("vcs %s: CheckReuse: %w", r.cmd.vcs, errors.ErrUnsupported)
}

func (r *vcsRepo) Tags(ctx context.Context, prefix string) (*Tags, error) {
	unlock, err := r.mu.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	r.tagsOnce.Do(func() { r.loadTags(ctx) })
	tags := &Tags{
		// None of the other VCS provide a reasonable way to compute TagSum
		// without downloading the whole repo, so we only include VCS and URL
		// in the Origin.
		Origin: &Origin{
			VCS: r.cmd.vcs,
			URL: r.remote,
		},
		List: []Tag{},
	}
	for tag := range r.tags {
		if strings.HasPrefix(tag, prefix) {
			tags.List = append(tags.List, Tag{tag, ""})
		}
	}
	sort.Slice(tags.List, func(i, j int) bool {
		return tags.List[i].Name < tags.List[j].Name
	})
	return tags, nil
}

func (r *vcsRepo) Stat(ctx context.Context, rev string) (*RevInfo, error) {
	unlock, err := r.mu.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	if rev == "latest" {
		rev = r.cmd.latest
	}
	r.branchesOnce.Do(func() { r.loadBranches(ctx) })
	if r.local {
		// Ignore the badLocalRevRE precondition in local only mode.
		// We cannot fetch latest upstream changes so only serve what's in the local cache.
		return r.statLocal(ctx, rev)
	}
	revOK := (r.cmd.badLocalRevRE == nil || !r.cmd.badLocalRevRE.MatchString(rev)) && !r.branches[rev]
	if revOK {
		if info, err := r.statLocal(ctx, rev); err == nil {
			return info, nil
		}
	}

	r.fetchOnce.Do(func() { r.fetch(ctx) })
	if r.fetchErr != nil {
		return nil, r.fetchErr
	}
	info, err := r.statLocal(ctx, rev)
	if err != nil {
		return nil, err
	}
	if !revOK {
		info.Version = info.Name
	}
	return info, nil
}

func (r *vcsRepo) fetch(ctx context.Context) {
	if len(r.cmd.fetch) > 0 {
		release, err := base.AcquireNet()
		if err != nil {
			r.fetchErr = err
			return
		}
		_, r.fetchErr = Run(ctx, r.dir, r.cmd.fetch)
		release()
	}
}

func (r *vcsRepo) statLocal(ctx context.Context, rev string) (*RevInfo, error) {
	out, err := Run(ctx, r.dir, r.cmd.statLocal(rev, r.remote))
	if err != nil {
		return nil, &UnknownRevisionError{Rev: rev}
	}
	info, err := r.cmd.parseStat(rev, string(out))
	if err != nil {
		return nil, err
	}
	if info.Origin == nil {
		info.Origin = new(Origin)
	}
	info.Origin.VCS = r.cmd.vcs
	info.Origin.URL = r.remote
	return info, nil
}

func (r *vcsRepo) Latest(ctx context.Context) (*RevInfo, error) {
	return r.Stat(ctx, "latest")
}

func (r *vcsRepo) ReadFile(ctx context.Context, rev, file string, maxSize int64) ([]byte, error) {
	if rev == "latest" {
		rev = r.cmd.latest
	}
	_, err := r.Stat(ctx, rev) // download rev into local repo
	if err != nil {
		return nil, err
	}

	// r.Stat acquires r.mu, so lock after that.
	unlock, err := r.mu.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	out, err := Run(ctx, r.dir, r.cmd.readFile(rev, file, r.remote))
	if err != nil {
		return nil, fs.ErrNotExist
	}
	return out, nil
}

func (r *vcsRepo) RecentTag(ctx context.Context, rev, prefix string, allowed func(string) bool) (tag string, err error) {
	// We don't technically need to lock here since we're returning an error
	// unconditionally, but doing so anyway will help to avoid baking in
	// lock-inversion bugs.
	unlock, err := r.mu.Lock()
	if err != nil {
		return "", err
	}
	defer unlock()

	return "", vcsErrorf("vcs %s: RecentTag: %w", r.cmd.vcs, errors.ErrUnsupported)
}

func (r *vcsRepo) DescendsFrom(ctx context.Context, rev, tag string) (bool, error) {
	unlock, err := r.mu.Lock()
	if err != nil {
		return false, err
	}
	defer unlock()

	return false, vcsErrorf("vcs %s: DescendsFrom: %w", r.cmd.vcs, errors.ErrUnsupported)
}

func (r *vcsRepo) ReadZip(ctx context.Context, rev, subdir string, maxSize int64) (zip io.ReadCloser, err error) {
	if r.cmd.readZip == nil && r.cmd.doReadZip == nil {
		return nil, vcsErrorf("vcs %s: ReadZip: %w", r.cmd.vcs, errors.ErrUnsupported)
	}

	unlock, err := r.mu.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	if rev == "latest" {
		rev = r.cmd.latest
	}
	f, err := os.CreateTemp("", "go-readzip-*.zip")
	if err != nil {
		return nil, err
	}
	if r.cmd.doReadZip != nil {
		lw := &limitedWriter{
			W:               f,
			N:               maxSize,
			ErrLimitReached: errors.New("ReadZip: encoded file exceeds allowed size"),
		}
		err = r.cmd.doReadZip(ctx, lw, r.dir, rev, subdir, r.remote)
		if err == nil {
			_, err = f.Seek(0, io.SeekStart)
		}
	} else if r.cmd.vcs == "fossil" {
		// If you run
		//	fossil zip -R .fossil --name prefix trunk /tmp/x.zip
		// fossil fails with "unable to create directory /tmp" [sic].
		// Change the command to run in /tmp instead,
		// replacing the -R argument with an absolute path.
		args := r.cmd.readZip(rev, subdir, r.remote, filepath.Base(f.Name()))
		for i := range args {
			if args[i] == ".fossil" {
				args[i] = filepath.Join(r.dir, ".fossil")
			}
		}
		_, err = Run(ctx, filepath.Dir(f.Name()), args)
	} else {
		_, err = Run(ctx, r.dir, r.cmd.readZip(rev, subdir, r.remote, f.Name()))
	}
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return &deleteCloser{f}, nil
}

// deleteCloser is a file that gets deleted on Close.
type deleteCloser struct {
	*os.File
}

func (d *deleteCloser) Close() error {
	defer os.Remove(d.File.Name())
	return d.File.Close()
}

func hgParseStat(rev, out string) (*RevInfo, error) {
	f := strings.Fields(out)
	if len(f) < 3 {
		return nil, vcsErrorf("unexpected response from hg log: %q", out)
	}
	hash := f[0]
	version := rev
	if strings.HasPrefix(hash, version) {
		version = hash // extend to full hash
	}
	t, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return nil, vcsErrorf("invalid time from hg log: %q", out)
	}

	var tags []string
	for _, tag := range f[3:] {
		if tag != "tip" {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)

	info := &RevInfo{
		Origin: &Origin{
			Hash: hash,
		},
		Name:    hash,
		Short:   ShortenSHA1(hash),
		Time:    time.Unix(t, 0).UTC(),
		Version: version,
		Tags:    tags,
	}
	return info, nil
}

func bzrParseStat(rev, out string) (*RevInfo, error) {
	var revno int64
	var tm time.Time
	var tags []string
	for _, line := range strings.Split(out, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			// End of header, start of commit message.
			break
		}
		if line[0] == '-' {
			continue
		}
		before, after, found := strings.Cut(line, ":")
		if !found {
			// End of header, start of commit message.
			break
		}
		key, val := before, strings.TrimSpace(after)
		switch key {
		case "revno":
			if j := strings.Index(val, " "); j >= 0 {
				val = val[:j]
			}
			i, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return nil, vcsErrorf("unexpected revno from bzr log: %q", line)
			}
			revno = i
		case "timestamp":
			j := strings.Index(val, " ")
			if j < 0 {
				return nil, vcsErrorf("unexpected timestamp from bzr log: %q", line)
			}
			t, err := time.Parse("2006-01-02 15:04:05 -0700", val[j+1:])
			if err != nil {
				return nil, vcsErrorf("unexpected timestamp from bzr log: %q", line)
			}
			tm = t.UTC()
		case "tags":
			tags = strings.Split(val, ", ")
		}
	}
	if revno == 0 || tm.IsZero() {
		return nil, vcsErrorf("unexpected response from bzr log: %q", out)
	}

	info := &RevInfo{
		Name:    strconv.FormatInt(revno, 10),
		Short:   fmt.Sprintf("%012d", revno),
		Time:    tm,
		Version: rev,
		Tags:    tags,
	}
	return info, nil
}

func fossilParseStat(rev, out string) (*RevInfo, error) {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "uuid:") || strings.HasPrefix(line, "hash:") {
			f := strings.Fields(line)
			if len(f) != 5 || len(f[1]) != 40 || f[4] != "UTC" {
				return nil, vcsErrorf("unexpected response from fossil info: %q", line)
			}
			t, err := time.Parse(time.DateTime, f[2]+" "+f[3])
			if err != nil {
				return nil, vcsErrorf("unexpected response from fossil info: %q", line)
			}
			hash := f[1]
			version := rev
			if strings.HasPrefix(hash, version) {
				version = hash // extend to full hash
			}
			info := &RevInfo{
				Origin: &Origin{
					Hash: hash,
				},
				Name:    hash,
				Short:   ShortenSHA1(hash),
				Time:    t,
				Version: version,
			}
			return info, nil
		}
	}
	return nil, vcsErrorf("unexpected response from fossil info: %q", out)
}

type limitedWriter struct {
	W               io.Writer
	N               int64
	ErrLimitReached error
}

func (l *limitedWriter) Write(p []byte) (n int, err error) {
	if l.N > 0 {
		max := len(p)
		if l.N < int64(max) {
			max = int(l.N)
		}
		n, err = l.W.Write(p[:max])
		l.N -= int64(n)
		if err != nil || n >= len(p) {
			return n, err
		}
	}

	return n, l.ErrLimitReached
}

"""



```