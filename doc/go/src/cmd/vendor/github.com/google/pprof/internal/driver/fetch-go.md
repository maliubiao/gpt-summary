Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The core request is to understand the functionality of `fetch.go` within the context of `pprof`. This implies focusing on how it retrieves profiling data.

2. **Identify Key Functions:**  A quick scan reveals several important function names:
    * `fetchProfiles`: This seems like the main entry point for fetching.
    * `grabSourcesAndBases`: The "grab" suggests retrieving data from multiple sources.
    * `chunkedGrab`:  "Chunked" implies processing data in parts, likely to manage memory.
    * `concurrentGrab`:  "Concurrent" indicates parallel processing for faster fetching.
    * `grabProfile`:  The singular "Profile" suggests fetching a single profile.
    * `combineProfiles`:  This likely merges multiple profiles.
    * `fetchURL`:  Specifically deals with fetching from URLs.
    * `fetch`:  A more general fetch function that seems to handle both files and URLs.
    * `adjustURL`:  Manipulates URLs, possibly adding parameters.
    * `locateBinaries`:  Deals with finding binary files.
    * `collectMappingSources`:  Gathers information about where mappings come from.
    * `unsourceMappings`:  Reverses the effect of `collectMappingSources` after symbolization.
    * `isPerfFile`, `convertPerfData`: Handle `perf.data` format.

3. **Trace the Execution Flow (Top-Down):**  Start with `fetchProfiles` and follow the logical steps:
    * It takes a `source` and `plugin.Options`. The `source` likely contains the locations of profiles to fetch.
    * It differentiates between `sources` and `bases`. This hints at the concept of diffing profiles.
    * It calls `grabSourcesAndBases` to actually retrieve the profiles.
    * It handles base profiles for diffing and normalization.
    * It calls `o.Sym.Symbolize` – a crucial step for converting raw addresses into meaningful symbols.
    * It removes "uninteresting" data.
    * It adds a comment.
    * It saves the merged profile to a temporary file if it came from a remote source.

4. **Deep Dive into Key Functions:**

    * **`grabSourcesAndBases`:**  Uses goroutines (`sync.WaitGroup`) to fetch sources and bases concurrently. This confirms the parallel processing idea. It handles errors and reports the number of fetched profiles.

    * **`chunkedGrab`:** Iterates through the `sources` in chunks and calls `concurrentGrab` for each chunk. This confirms the memory management strategy.

    * **`concurrentGrab`:** Again, uses goroutines to fetch individual profiles. It calls `grabProfile` for each source.

    * **`grabProfile`:**  This is where the actual fetching happens. It first tries a `fetcher` (likely a more specialized way to get profiles) and falls back to the generic `fetch` function. It also handles binary location (`locateBinaries`) and collects mapping sources.

    * **`fetch`:** Handles both file paths (using `os.Open` and checking for `perf.data`) and URLs (using `fetchURL`). This is the core data retrieval logic.

    * **`fetchURL`:**  Performs the HTTP GET request with a timeout.

    * **`locateBinaries`:**  This is about finding the actual binary files associated with the profile. It checks environment variables (`PPROF_BINARY_PATH`) and tries different file naming conventions. This is essential for symbolization.

    * **`combineProfiles`:** Merges the fetched profiles, handling sample type compatibility.

5. **Identify Go Features:**  As you go through the code, note the Go language features being used:
    * Goroutines and `sync.WaitGroup` for concurrency.
    * Interfaces (`plugin.Fetcher`, `plugin.ObjTool`, `plugin.UI`, `http.RoundTripper`) for abstraction and extensibility.
    * Error handling (`error` type, `if err != nil`).
    * Standard library packages like `net/http`, `os`, `io`, `time`, `strings`, `path/filepath`, `strconv`, `net/url`.
    * Structs for data organization (`source`, `profileSource`).

6. **Construct Examples:** For important functionalities, create simplified Go code examples to illustrate their usage. This helps solidify understanding. For example, showing how `fetchURL` makes an HTTP request or how `os.Stat` checks for a file.

7. **Command-Line Parameter Handling:**  Focus on how the code interacts with input related to fetching. The `source` struct and `plugin.Options` are key here. The code handles both file paths and URLs. The `adjustURL` function demonstrates how URL parameters (like `seconds`) can influence the fetching process.

8. **Identify Potential Pitfalls:** Think about common errors users might make. Not understanding the difference between `sources` and `bases`, issues with binary paths for symbolization, or problems with network connectivity when fetching remote profiles are good candidates.

9. **Structure the Answer:** Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the key functionalities, explaining each one.
    * Provide illustrative Go code examples.
    * Explain command-line parameter handling.
    * List potential user errors.

10. **Refine and Review:** Read through the generated answer, ensuring clarity, accuracy, and completeness. Make sure the explanations are easy to understand, especially for someone who might not be deeply familiar with the `pprof` codebase. For example, explain *why* `locateBinaries` is important (for symbolization).

By following these steps, a comprehensive and accurate understanding of the `fetch.go` file can be achieved, addressing all the requirements of the prompt. The key is to combine code reading with an understanding of the broader purpose of the software and common programming patterns.
这段代码是 Go 语言 `pprof` 工具的一部分，位于 `go/src/cmd/vendor/github.com/google/pprof/internal/driver/fetch.go`，其主要功能是**从不同的来源获取性能剖析数据（profile）并进行初步处理**。

更具体地说，它实现了以下功能：

1. **支持多种 profile 来源:**
   - **本地文件:** 可以直接读取本地的 `.pb.gz` 格式的 profile 文件。
   - **HTTP(S) URL:** 可以通过 HTTP(S) 请求从远程服务器获取 profile 数据。支持在 URL 中指定 `seconds` 参数来控制获取 profile 的时间长度。
   - **`perf.data` 文件:**  能够识别 Linux `perf` 工具生成的 `perf.data` 文件，并使用 `perf_to_profile` 工具将其转换为 `pprof` 可用的 profile 格式。
   - **自定义的 `plugin.Fetcher`:**  允许通过插件机制扩展支持其他的 profile 获取方式。

2. **并发获取多个 profile:**  `fetchProfiles` 函数可以处理多个 profile 来源，并使用 goroutine 并发地获取它们，提高效率。

3. **支持基准 profile (base profile) 进行差分:**  可以指定一个或多个基准 profile，用于与主 profile 进行比较，以突出性能变化。

4. **规范化 (Normalize) 和差分 (Diff):**  在指定了基准 profile 的情况下，可以对主 profile 进行规范化处理，并与基准 profile 进行差分计算。

5. **符号化 (Symbolize):**  调用 `o.Sym.Symbolize` 方法，利用二进制文件中的调试信息将 profile 中的地址转换为人类可读的符号信息。

6. **移除不感兴趣的数据:**  调用 `p.RemoveUninteresting()` 清理 profile 中不必要的数据。

7. **保存临时的 profile 文件:**  如果 profile 来自远程源，它会将合并后的 profile 保存到临时文件中，方便后续分析。

8. **处理二进制文件定位:**  `locateBinaries` 函数会尝试根据 profile 中记录的二进制文件名和 BuildID 在本地文件系统中查找对应的二进制文件，以便进行符号化。它会搜索 `PPROF_BINARY_PATH` 环境变量指定的路径，以及一些常见的调试符号文件位置。

9. **处理 URL 参数:** `adjustURL` 函数解析 URL，并处理 `seconds` 参数，用于控制 profile 的采样时长。

**推理其实现的 Go 语言功能:**

这段代码主要使用了 Go 语言的以下功能：

* **Goroutines 和 `sync.WaitGroup`:**  用于实现并发操作，例如并发地获取多个 profile。
* **HTTP 客户端 (`net/http`)**:  用于发送 HTTP 请求获取远程 profile 数据。
* **文件操作 (`os` 包):**  用于读取本地 profile 文件，创建临时文件等。
* **命令行参数处理 (通过 `plugin.Options` 和 `source` 结构体):**  虽然这段代码本身没有直接处理 `flag` 包，但它接收的 `source` 结构体很可能是由命令行参数解析得到的。
* **字符串操作 (`strings` 包):**  用于处理 URL，文件名等字符串。
* **路径操作 (`path/filepath` 包):**  用于处理文件路径。
* **时间操作 (`time` 包):**  用于设置超时时间和处理 duration 参数。
* **错误处理 (`error` 类型):**  用于报告 profile 获取和处理过程中出现的错误。
* **接口 (`plugin.Fetcher`, `plugin.ObjTool`, `plugin.UI`, `http.RoundTripper`):**  使用接口来实现插件化和抽象，例如 `plugin.Fetcher` 用于抽象不同的 profile 获取方式，`plugin.ObjTool` 用于操作二进制文件。

**Go 代码举例说明:**

以下代码演示了 `fetchURL` 函数如何使用 `net/http` 包来获取远程 profile：

```go
package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func fetchURL(source string, timeout time.Duration) (io.ReadCloser, error) {
	client := &http.Client{
		Timeout: timeout + 5*time.Second,
	}
	resp, err := client.Get(source)
	if err != nil {
		return nil, fmt.Errorf("http fetch: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("server response: %s", resp.Status)
	}
	return resp.Body, nil
}

func main() {
	url := "http://example.com/debug/pprof/profile?seconds=1"
	timeout := 10 * time.Second
	body, err := fetchURL(url, timeout)
	if err != nil {
		fmt.Println("Error fetching URL:", err)
		return
	}
	defer body.Close()

	content, err := io.ReadAll(body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}
	fmt.Println("Profile content:", string(content))
}
```

**假设的输入与输出:**

假设我们有一个 `source` 结构体，其中包含一个 HTTP URL 作为 profile 来源：

```go
package main

import "time"

type source struct {
	Sources  []string
	Base     []string
	DiffBase bool
	Normalize bool
	Symbolize []string
	Comment   string
	Seconds   int
	Timeout   int
	ExecName  string
	BuildID   string
}

func main() {
	s := &source{
		Sources: []string{"http://localhost:6060/debug/pprof/profile?seconds=5"},
		Timeout: 10,
	}
	// ... 调用 fetchProfiles 函数，此处省略 ...
}
```

**输入:** `s` 结构体包含 profile 来源的 URL，以及超时时间等配置。

**输出:** `fetchProfiles` 函数会尝试从 `http://localhost:6060/debug/pprof/profile?seconds=5` 获取 profile 数据。如果成功，它会返回一个 `*profile.Profile` 对象，其中包含了从该 URL 获取的性能剖析数据。如果失败，则返回一个 `error`。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的解析通常发生在 `pprof` 工具的主入口点。但是，我们可以推断出 `source` 结构体的字段很可能对应于一些命令行参数，例如：

* `-source` 或直接提供 URL 作为参数：对应 `s.Sources`
* `-base`：对应 `s.Base`
* `-diff_base`：对应 `s.DiffBase`
* `-normalize`：对应 `s.Normalize`
* `-symbolize`：对应 `s.Symbolize`
* `-comment`：对应 `s.Comment`
* `-seconds`：对应 `s.Seconds`
* `-timeout`：对应 `s.Timeout`
* `-exec`：对应 `s.ExecName`
* `-buildid`：对应 `s.BuildID`

例如，当用户在命令行输入 `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=10` 时，`pprof` 工具会解析这个 URL，并创建一个 `source` 结构体，其中 `s.Sources` 将包含 `"http://localhost:6060/debug/pprof/profile?seconds=10"`。

**使用者易犯错的点:**

1. **忘记启动目标程序的 pprof endpoint:**  如果要从 HTTP URL 获取 profile，目标程序必须已经启动，并且暴露了 `/debug/pprof/` endpoint。

   **错误示例:**  目标程序未运行，执行 `go tool pprof http://localhost:6060/debug/pprof/profile` 会导致连接错误。

2. **URL 地址错误或拼写错误:**  输入的 URL 地址不正确，或者存在拼写错误，会导致无法找到 profile 数据。

   **错误示例:**  输入 `go tool pprof http://localhost:6060/debuge/pprof/profile` (将 `debug` 拼写成了 `debuge`) 会导致 404 错误。

3. **权限问题:**  访问本地 profile 文件时，可能由于权限不足导致读取失败。

   **错误示例:**  尝试访问一个只有 root 用户才能读取的 profile 文件，普通用户执行 `go tool pprof /root/profile.pb.gz` 会导致权限错误。

4. **网络问题:**  在获取远程 profile 时，网络连接不稳定或者存在防火墙限制，会导致获取失败。

   **错误示例:**  在网络断开的情况下执行 `go tool pprof http://remoteserver:6060/debug/pprof/profile` 会导致连接超时或网络错误。

5. **不理解 `seconds` 参数的作用:**  用户可能没有意识到可以在 URL 中使用 `seconds` 参数来控制 profile 的采样时长，导致获取的 profile 数据不完整或者时间过长。

   **错误示例:**  直接使用 `go tool pprof http://localhost:6060/debug/pprof/profile`，可能会获取到默认较短时间的 profile，无法分析长时间运行的问题。应该使用 `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=60` 来获取更长时间的 profile。

总而言之，`fetch.go` 文件在 `pprof` 工具中扮演着至关重要的角色，它负责从各种来源获取原始的性能剖析数据，为后续的分析、可视化等操作奠定了基础。

### 提示词
```
这是路径为go/src/cmd/vendor/github.com/google/pprof/internal/driver/fetch.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package driver

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/pprof/internal/measurement"
	"github.com/google/pprof/internal/plugin"
	"github.com/google/pprof/profile"
)

// fetchProfiles fetches and symbolizes the profiles specified by s.
// It will merge all the profiles it is able to retrieve, even if
// there are some failures. It will return an error if it is unable to
// fetch any profiles.
func fetchProfiles(s *source, o *plugin.Options) (*profile.Profile, error) {
	sources := make([]profileSource, 0, len(s.Sources))
	for _, src := range s.Sources {
		sources = append(sources, profileSource{
			addr:   src,
			source: s,
		})
	}

	bases := make([]profileSource, 0, len(s.Base))
	for _, src := range s.Base {
		bases = append(bases, profileSource{
			addr:   src,
			source: s,
		})
	}

	p, pbase, m, mbase, save, err := grabSourcesAndBases(sources, bases, o.Fetch, o.Obj, o.UI, o.HTTPTransport)
	if err != nil {
		return nil, err
	}

	if pbase != nil {
		if s.DiffBase {
			pbase.SetLabel("pprof::base", []string{"true"})
		}
		if s.Normalize {
			err := p.Normalize(pbase)
			if err != nil {
				return nil, err
			}
		}
		pbase.Scale(-1)
		p, m, err = combineProfiles([]*profile.Profile{p, pbase}, []plugin.MappingSources{m, mbase})
		if err != nil {
			return nil, err
		}
	}

	// Symbolize the merged profile.
	if err := o.Sym.Symbolize(s.Symbolize, m, p); err != nil {
		return nil, err
	}
	p.RemoveUninteresting()
	unsourceMappings(p)

	if s.Comment != "" {
		p.Comments = append(p.Comments, s.Comment)
	}

	// Save a copy of the merged profile if there is at least one remote source.
	if save {
		dir, err := setTmpDir(o.UI)
		if err != nil {
			return nil, err
		}

		prefix := "pprof."
		if len(p.Mapping) > 0 && p.Mapping[0].File != "" {
			prefix += filepath.Base(p.Mapping[0].File) + "."
		}
		for _, s := range p.SampleType {
			prefix += s.Type + "."
		}

		tempFile, err := newTempFile(dir, prefix, ".pb.gz")
		if err == nil {
			if err = p.Write(tempFile); err == nil {
				o.UI.PrintErr("Saved profile in ", tempFile.Name())
			}
		}
		if err != nil {
			o.UI.PrintErr("Could not save profile: ", err)
		}
	}

	if err := p.CheckValid(); err != nil {
		return nil, err
	}

	return p, nil
}

func grabSourcesAndBases(sources, bases []profileSource, fetch plugin.Fetcher, obj plugin.ObjTool, ui plugin.UI, tr http.RoundTripper) (*profile.Profile, *profile.Profile, plugin.MappingSources, plugin.MappingSources, bool, error) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	var psrc, pbase *profile.Profile
	var msrc, mbase plugin.MappingSources
	var savesrc, savebase bool
	var errsrc, errbase error
	var countsrc, countbase int
	go func() {
		defer wg.Done()
		psrc, msrc, savesrc, countsrc, errsrc = chunkedGrab(sources, fetch, obj, ui, tr)
	}()
	go func() {
		defer wg.Done()
		pbase, mbase, savebase, countbase, errbase = chunkedGrab(bases, fetch, obj, ui, tr)
	}()
	wg.Wait()
	save := savesrc || savebase

	if errsrc != nil {
		return nil, nil, nil, nil, false, fmt.Errorf("problem fetching source profiles: %v", errsrc)
	}
	if errbase != nil {
		return nil, nil, nil, nil, false, fmt.Errorf("problem fetching base profiles: %v,", errbase)
	}
	if countsrc == 0 {
		return nil, nil, nil, nil, false, fmt.Errorf("failed to fetch any source profiles")
	}
	if countbase == 0 && len(bases) > 0 {
		return nil, nil, nil, nil, false, fmt.Errorf("failed to fetch any base profiles")
	}
	if want, got := len(sources), countsrc; want != got {
		ui.PrintErr(fmt.Sprintf("Fetched %d source profiles out of %d", got, want))
	}
	if want, got := len(bases), countbase; want != got {
		ui.PrintErr(fmt.Sprintf("Fetched %d base profiles out of %d", got, want))
	}

	return psrc, pbase, msrc, mbase, save, nil
}

// chunkedGrab fetches the profiles described in source and merges them into
// a single profile. It fetches a chunk of profiles concurrently, with a maximum
// chunk size to limit its memory usage.
func chunkedGrab(sources []profileSource, fetch plugin.Fetcher, obj plugin.ObjTool, ui plugin.UI, tr http.RoundTripper) (*profile.Profile, plugin.MappingSources, bool, int, error) {
	const chunkSize = 128

	var p *profile.Profile
	var msrc plugin.MappingSources
	var save bool
	var count int

	for start := 0; start < len(sources); start += chunkSize {
		end := start + chunkSize
		if end > len(sources) {
			end = len(sources)
		}
		chunkP, chunkMsrc, chunkSave, chunkCount, chunkErr := concurrentGrab(sources[start:end], fetch, obj, ui, tr)
		switch {
		case chunkErr != nil:
			return nil, nil, false, 0, chunkErr
		case chunkP == nil:
			continue
		case p == nil:
			p, msrc, save, count = chunkP, chunkMsrc, chunkSave, chunkCount
		default:
			p, msrc, chunkErr = combineProfiles([]*profile.Profile{p, chunkP}, []plugin.MappingSources{msrc, chunkMsrc})
			if chunkErr != nil {
				return nil, nil, false, 0, chunkErr
			}
			if chunkSave {
				save = true
			}
			count += chunkCount
		}
	}

	return p, msrc, save, count, nil
}

// concurrentGrab fetches multiple profiles concurrently
func concurrentGrab(sources []profileSource, fetch plugin.Fetcher, obj plugin.ObjTool, ui plugin.UI, tr http.RoundTripper) (*profile.Profile, plugin.MappingSources, bool, int, error) {
	wg := sync.WaitGroup{}
	wg.Add(len(sources))
	for i := range sources {
		go func(s *profileSource) {
			defer wg.Done()
			s.p, s.msrc, s.remote, s.err = grabProfile(s.source, s.addr, fetch, obj, ui, tr)
		}(&sources[i])
	}
	wg.Wait()

	var save bool
	profiles := make([]*profile.Profile, 0, len(sources))
	msrcs := make([]plugin.MappingSources, 0, len(sources))
	for i := range sources {
		s := &sources[i]
		if err := s.err; err != nil {
			ui.PrintErr(s.addr + ": " + err.Error())
			continue
		}
		save = save || s.remote
		profiles = append(profiles, s.p)
		msrcs = append(msrcs, s.msrc)
		*s = profileSource{}
	}

	if len(profiles) == 0 {
		return nil, nil, false, 0, nil
	}

	p, msrc, err := combineProfiles(profiles, msrcs)
	if err != nil {
		return nil, nil, false, 0, err
	}
	return p, msrc, save, len(profiles), nil
}

func combineProfiles(profiles []*profile.Profile, msrcs []plugin.MappingSources) (*profile.Profile, plugin.MappingSources, error) {
	// Merge profiles.
	//
	// The merge call below only treats exactly matching sample type lists as
	// compatible and will fail otherwise. Make the profiles' sample types
	// compatible for the merge, see CompatibilizeSampleTypes() doc for details.
	if err := profile.CompatibilizeSampleTypes(profiles); err != nil {
		return nil, nil, err
	}
	if err := measurement.ScaleProfiles(profiles); err != nil {
		return nil, nil, err
	}

	// Avoid expensive work for the common case of a single profile/src.
	if len(profiles) == 1 && len(msrcs) == 1 {
		return profiles[0], msrcs[0], nil
	}

	p, err := profile.Merge(profiles)
	if err != nil {
		return nil, nil, err
	}

	// Combine mapping sources.
	msrc := make(plugin.MappingSources)
	for _, ms := range msrcs {
		for m, s := range ms {
			msrc[m] = append(msrc[m], s...)
		}
	}
	return p, msrc, nil
}

type profileSource struct {
	addr   string
	source *source

	p      *profile.Profile
	msrc   plugin.MappingSources
	remote bool
	err    error
}

func homeEnv() string {
	switch runtime.GOOS {
	case "windows":
		return "USERPROFILE"
	case "plan9":
		return "home"
	default:
		return "HOME"
	}
}

// setTmpDir prepares the directory to use to save profiles retrieved
// remotely. It is selected from PPROF_TMPDIR, defaults to $HOME/pprof, and, if
// $HOME is not set, falls back to os.TempDir().
func setTmpDir(ui plugin.UI) (string, error) {
	var dirs []string
	if profileDir := os.Getenv("PPROF_TMPDIR"); profileDir != "" {
		dirs = append(dirs, profileDir)
	}
	if homeDir := os.Getenv(homeEnv()); homeDir != "" {
		dirs = append(dirs, filepath.Join(homeDir, "pprof"))
	}
	dirs = append(dirs, os.TempDir())
	for _, tmpDir := range dirs {
		if err := os.MkdirAll(tmpDir, 0755); err != nil {
			ui.PrintErr("Could not use temp dir ", tmpDir, ": ", err.Error())
			continue
		}
		return tmpDir, nil
	}
	return "", fmt.Errorf("failed to identify temp dir")
}

const testSourceAddress = "pproftest.local"

// grabProfile fetches a profile. Returns the profile, sources for the
// profile mappings, a bool indicating if the profile was fetched
// remotely, and an error.
func grabProfile(s *source, source string, fetcher plugin.Fetcher, obj plugin.ObjTool, ui plugin.UI, tr http.RoundTripper) (p *profile.Profile, msrc plugin.MappingSources, remote bool, err error) {
	var src string
	duration, timeout := time.Duration(s.Seconds)*time.Second, time.Duration(s.Timeout)*time.Second
	if fetcher != nil {
		p, src, err = fetcher.Fetch(source, duration, timeout)
		if err != nil {
			return
		}
	}
	if err != nil || p == nil {
		// Fetch the profile over HTTP or from a file.
		p, src, err = fetch(source, duration, timeout, ui, tr)
		if err != nil {
			return
		}
	}

	if err = p.CheckValid(); err != nil {
		return
	}

	// Update the binary locations from command line and paths.
	locateBinaries(p, s, obj, ui)

	// Collect the source URL for all mappings.
	if src != "" {
		msrc = collectMappingSources(p, src)
		remote = true
		if strings.HasPrefix(src, "http://"+testSourceAddress) {
			// Treat test inputs as local to avoid saving
			// testcase profiles during driver testing.
			remote = false
		}
	}
	return
}

// collectMappingSources saves the mapping sources of a profile.
func collectMappingSources(p *profile.Profile, source string) plugin.MappingSources {
	ms := plugin.MappingSources{}
	for _, m := range p.Mapping {
		src := struct {
			Source string
			Start  uint64
		}{
			source, m.Start,
		}
		key := m.BuildID
		if key == "" {
			key = m.File
		}
		if key == "" {
			// If there is no build id or source file, use the source as the
			// mapping file. This will enable remote symbolization for this
			// mapping, in particular for Go profiles on the legacy format.
			// The source is reset back to empty string by unsourceMapping
			// which is called after symbolization is finished.
			m.File = source
			key = source
		}
		ms[key] = append(ms[key], src)
	}
	return ms
}

// unsourceMappings iterates over the mappings in a profile and replaces file
// set to the remote source URL by collectMappingSources back to empty string.
func unsourceMappings(p *profile.Profile) {
	for _, m := range p.Mapping {
		if m.BuildID == "" && filepath.VolumeName(m.File) == "" {
			if u, err := url.Parse(m.File); err == nil && u.IsAbs() {
				m.File = ""
			}
		}
	}
}

// locateBinaries searches for binary files listed in the profile and, if found,
// updates the profile accordingly.
func locateBinaries(p *profile.Profile, s *source, obj plugin.ObjTool, ui plugin.UI) {
	// Construct search path to examine
	searchPath := os.Getenv("PPROF_BINARY_PATH")
	if searchPath == "" {
		// Use $HOME/pprof/binaries as default directory for local symbolization binaries
		searchPath = filepath.Join(os.Getenv(homeEnv()), "pprof", "binaries")
	}
mapping:
	for _, m := range p.Mapping {
		var noVolumeFile string
		var baseName string
		var dirName string
		if m.File != "" {
			noVolumeFile = strings.TrimPrefix(m.File, filepath.VolumeName(m.File))
			baseName = filepath.Base(m.File)
			dirName = filepath.Dir(noVolumeFile)
		}

		for _, path := range filepath.SplitList(searchPath) {
			var fileNames []string
			if m.BuildID != "" {
				fileNames = []string{filepath.Join(path, m.BuildID, baseName)}
				if matches, err := filepath.Glob(filepath.Join(path, m.BuildID, "*")); err == nil {
					fileNames = append(fileNames, matches...)
				}
				fileNames = append(fileNames, filepath.Join(path, noVolumeFile, m.BuildID)) // perf path format
				// Llvm buildid protocol: the first two characters of the build id
				// are used as directory, and the remaining part is in the filename.
				// e.g. `/ab/cdef0123456.debug`
				fileNames = append(fileNames, filepath.Join(path, m.BuildID[:2], m.BuildID[2:]+".debug"))
			}
			if m.File != "" {
				// Try both the basename and the full path, to support the same directory
				// structure as the perf symfs option.
				fileNames = append(fileNames, filepath.Join(path, baseName))
				fileNames = append(fileNames, filepath.Join(path, noVolumeFile))
				// Other locations: use the same search paths as GDB, according to
				// https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html
				fileNames = append(fileNames, filepath.Join(path, noVolumeFile+".debug"))
				fileNames = append(fileNames, filepath.Join(path, dirName, ".debug", baseName+".debug"))
				fileNames = append(fileNames, filepath.Join(path, "usr", "lib", "debug", dirName, baseName+".debug"))
			}
			for _, name := range fileNames {
				if f, err := obj.Open(name, m.Start, m.Limit, m.Offset, m.KernelRelocationSymbol); err == nil {
					defer f.Close()
					fileBuildID := f.BuildID()
					if m.BuildID != "" && m.BuildID != fileBuildID {
						ui.PrintErr("Ignoring local file " + name + ": build-id mismatch (" + m.BuildID + " != " + fileBuildID + ")")
					} else {
						// Explicitly do not update KernelRelocationSymbol --
						// the new local file name is most likely missing it.
						m.File = name
						continue mapping
					}
				}
			}
		}
	}
	if len(p.Mapping) == 0 {
		// If there are no mappings, add a fake mapping to attempt symbolization.
		// This is useful for some profiles generated by the golang runtime, which
		// do not include any mappings. Symbolization with a fake mapping will only
		// be successful against a non-PIE binary.
		m := &profile.Mapping{ID: 1}
		p.Mapping = []*profile.Mapping{m}
		for _, l := range p.Location {
			l.Mapping = m
		}
	}
	// If configured, apply executable filename override and (maybe, see below)
	// build ID override from source. Assume the executable is the first mapping.
	if execName, buildID := s.ExecName, s.BuildID; execName != "" || buildID != "" {
		m := p.Mapping[0]
		if execName != "" {
			// Explicitly do not update KernelRelocationSymbol --
			// the source override is most likely missing it.
			m.File = execName
		}
		// Only apply the build ID override if the build ID in the main mapping is
		// missing. Overwriting the build ID in case it's present is very likely a
		// wrong thing to do so we refuse to do that.
		if buildID != "" && m.BuildID == "" {
			m.BuildID = buildID
		}
	}
}

// fetch fetches a profile from source, within the timeout specified,
// producing messages through the ui. It returns the profile and the
// url of the actual source of the profile for remote profiles.
func fetch(source string, duration, timeout time.Duration, ui plugin.UI, tr http.RoundTripper) (p *profile.Profile, src string, err error) {
	var f io.ReadCloser

	// First determine whether the source is a file, if not, it will be treated as a URL.
	if _, err = os.Stat(source); err == nil {
		if isPerfFile(source) {
			f, err = convertPerfData(source, ui)
		} else {
			f, err = os.Open(source)
		}
	} else {
		sourceURL, timeout := adjustURL(source, duration, timeout)
		if sourceURL != "" {
			ui.Print("Fetching profile over HTTP from " + sourceURL)
			if duration > 0 {
				ui.Print(fmt.Sprintf("Please wait... (%v)", duration))
			}
			f, err = fetchURL(sourceURL, timeout, tr)
			src = sourceURL
		}
	}
	if err == nil {
		defer f.Close()
		p, err = profile.Parse(f)
	}
	return
}

// fetchURL fetches a profile from a URL using HTTP.
func fetchURL(source string, timeout time.Duration, tr http.RoundTripper) (io.ReadCloser, error) {
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout + 5*time.Second,
	}
	resp, err := client.Get(source)
	if err != nil {
		return nil, fmt.Errorf("http fetch: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, statusCodeError(resp)
	}

	return resp.Body, nil
}

func statusCodeError(resp *http.Response) error {
	if resp.Header.Get("X-Go-Pprof") != "" && strings.Contains(resp.Header.Get("Content-Type"), "text/plain") {
		// error is from pprof endpoint
		if body, err := io.ReadAll(resp.Body); err == nil {
			return fmt.Errorf("server response: %s - %s", resp.Status, body)
		}
	}
	return fmt.Errorf("server response: %s", resp.Status)
}

// isPerfFile checks if a file is in perf.data format. It also returns false
// if it encounters an error during the check.
func isPerfFile(path string) bool {
	sourceFile, openErr := os.Open(path)
	if openErr != nil {
		return false
	}
	defer sourceFile.Close()

	// If the file is the output of a perf record command, it should begin
	// with the string PERFILE2.
	perfHeader := []byte("PERFILE2")
	actualHeader := make([]byte, len(perfHeader))
	if _, readErr := sourceFile.Read(actualHeader); readErr != nil {
		return false
	}
	return bytes.Equal(actualHeader, perfHeader)
}

// convertPerfData converts the file at path which should be in perf.data format
// using the perf_to_profile tool and returns the file containing the
// profile.proto formatted data.
func convertPerfData(perfPath string, ui plugin.UI) (*os.File, error) {
	ui.Print(fmt.Sprintf(
		"Converting %s to a profile.proto... (May take a few minutes)",
		perfPath))
	profile, err := newTempFile(os.TempDir(), "pprof_", ".pb.gz")
	if err != nil {
		return nil, err
	}
	deferDeleteTempFile(profile.Name())
	cmd := exec.Command("perf_to_profile", "-i", perfPath, "-o", profile.Name(), "-f")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		profile.Close()
		return nil, fmt.Errorf("failed to convert perf.data file. Try github.com/google/perf_data_converter: %v", err)
	}
	return profile, nil
}

// adjustURL validates if a profile source is a URL and returns an
// cleaned up URL and the timeout to use for retrieval over HTTP.
// If the source cannot be recognized as a URL it returns an empty string.
func adjustURL(source string, duration, timeout time.Duration) (string, time.Duration) {
	u, err := url.Parse(source)
	if err != nil || (u.Host == "" && u.Scheme != "" && u.Scheme != "file") {
		// Try adding http:// to catch sources of the form hostname:port/path.
		// url.Parse treats "hostname" as the scheme.
		u, err = url.Parse("http://" + source)
	}
	if err != nil || u.Host == "" {
		return "", 0
	}

	// Apply duration/timeout overrides to URL.
	values := u.Query()
	if duration > 0 {
		values.Set("seconds", fmt.Sprint(int(duration.Seconds())))
	} else {
		if urlSeconds := values.Get("seconds"); urlSeconds != "" {
			if us, err := strconv.ParseInt(urlSeconds, 10, 32); err == nil {
				duration = time.Duration(us) * time.Second
			}
		}
	}
	if timeout <= 0 {
		if duration > 0 {
			timeout = duration + duration/2
		} else {
			timeout = 60 * time.Second
		}
	}
	u.RawQuery = values.Encode()
	return u.String(), timeout
}
```