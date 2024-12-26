Response: Let's break down the thought process for analyzing the provided Go code and generating the response.

**1. Understanding the Goal:**

The request asks for a breakdown of the `vcweb.go` file's functionality. Specifically, it wants:

* A list of its functions.
* An inference about its broader Go language feature implementation.
* Code examples to illustrate the functionality.
* Details about command-line parameter handling.
* Common pitfalls for users.

**2. Initial Code Scan and High-Level Understanding:**

The first step is a quick skim of the code, paying attention to package names, imports, type definitions, and key function names.

* **Package Name:** `vcweb` immediately suggests it's related to version control and the web.
* **Imports:**  `net/http`, `os`, `os/exec`, `path`, `sync`, `io` are strong indicators of a web server interacting with the file system and potentially external commands. The presence of `cmd/internal/script` is crucial – this hints at a scripting capability.
* **Type Definitions:** `Server`, `vcsHandler`, `scriptResult` are the main structural elements. `Server` is likely the core type. `vcsHandler` suggests handling different version control systems. `scriptResult` implies caching of script execution outcomes.
* **Key Functions:** `NewServer`, `ServeHTTP`, `HandleScript`, `overview`, `help`, and the `Close` method stand out as important entry points or core logic.

From this initial scan, the core idea emerges:  `vcweb` is a web server that dynamically generates version control repositories based on scripts.

**3. Detailed Analysis of Key Components:**

Now, we dive deeper into the important parts identified above.

* **`Server` struct:**  The fields (`env`, `logger`, `scriptDir`, `workDir`, `homeDir`, `engine`, `scriptCache`, `vcsHandlers`) provide clues about its responsibilities: managing environment variables, logging, finding scripts, handling working directories, running scripts, caching results, and supporting different VCS types.
* **`vcsHandler` interface:** This confirms the support for multiple VCS. The `Available()` and `Handler()` methods suggest a way to check if a VCS is installed and to create HTTP handlers for it.
* **`scriptResult` struct:** The `hash`, `hashTime`, `handler`, and `err` fields clearly show that script execution results are cached, including the script's content hash for invalidation.
* **`NewServer` function:** This is the constructor. It takes `scriptDir` and `workDir` as input, implying configuration via these paths. It initializes the `engine` and `vcsHandlers`. The creation of `.gitconfig` and `.hgrc` files provides direct evidence of Git and Mercurial support.
* **`ServeHTTP` function:**  This is the heart of the web server. It handles incoming requests. The logic to find the correct script based on the URL path is significant. The call to `HandleScript` is the central point where script execution happens.
* **`HandleScript` function:** This function manages the script execution and caching. The logic for checking the script's hash and regenerating output if it changes is a key part of its functionality. The use of `sync.Map` and `sync.RWMutex` indicates concurrent access handling.
* **`overview` function:**  This provides a basic listing of available scripts and their status.
* **`help` function:** This uses the script engine to generate help documentation.

**4. Inferring the Go Language Feature:**

Based on the analysis, the primary Go language feature being implemented is **testing infrastructure for Go commands that interact with version control systems.** The `cmd/go` path strongly suggests this. The dynamic generation of repositories allows for testing different VCS scenarios without needing pre-existing, fixed repositories.

**5. Creating Code Examples:**

To illustrate, we need to demonstrate:

* **Server creation:** Show how to use `NewServer`.
* **Basic script:** Create a simple script that `vcweb` can execute.
* **Accessing through HTTP:** Demonstrate how a client would interact with the `vcweb` server.

The examples should be concise and highlight the core interaction.

**6. Identifying Command-Line Parameters:**

The documentation within the code itself provides the crucial clue: `go test cmd/go/internal/vcweb/vcstest -v --port=0`. This clearly indicates the `-port` parameter and its purpose.

**7. Recognizing Potential User Errors:**

The caching mechanism based on script content is a potential source of confusion. Users might modify a script and expect immediate changes without understanding the caching. The need for the VCS binaries to be installed is another potential pitfall.

**8. Structuring the Response:**

Finally, the information needs to be organized logically, following the structure requested in the initial prompt. This includes:

* A clear list of functionalities.
* A well-articulated inference about the Go feature.
* Correctly formatted and runnable Go code examples with expected input and output.
* A detailed explanation of the command-line parameter.
* Specific examples of potential user errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe it's just a generic web server. *Correction:* The `vcsHandler` interface and the specific VCS names (git, hg, bzr, etc.) strongly point to version control.
* **Initial thought:** The scripts are just static files. *Correction:* The `script.Engine` and the dynamic regeneration logic in `HandleScript` prove they are interpreted and executed.
* **Missing detail:**  Initially, I might have overlooked the significance of the `.gitconfig` and `.hgrc` files. Recognizing their purpose strengthens the understanding of VCS support.
* **Example clarity:**  Ensuring the code examples are simple and easy to understand is important. Avoiding overly complex scripts or HTTP interactions makes the illustration clearer.

By following this detailed analysis and refinement process, the comprehensive and accurate response can be generated.
`go/src/cmd/go/internal/vcweb/vcweb.go` implements a web server that dynamically serves version control repositories for testing the `go` command. Here's a breakdown of its functionality:

**Core Functionality:**

1. **Dynamic Repository Generation:**
   - When a repository URL is requested for the first time, the server uses a script (interpreted by `cmd/internal/script`) to generate the repository's contents on demand.
   - This script defines the file structure and content for the repository.

2. **Script-Based Configuration:**
   - The server uses text files (with the `.txt` extension) as scripts to define the repositories.
   - The path of the requested URL maps to the location of the script files. For example, a request for `/foo/bar` might be served by a script at `$scriptDir/foo/bar.txt`.

3. **Caching:**
   - Once a script is executed and a repository is generated, the results (the HTTP handler for serving the repository) are cached.
   - Subsequent requests for the same URL (or any URL generated by the same script) will be served from the cache, improving performance.
   - The cache is invalidated if the script file is modified.

4. **Version Control System Support:**
   - The script engine provides commands to interact with various version control systems: `bzr`, `fossil`, `git`, `hg`, and `svn`.
   - This allows the scripts to create repositories in different VCS formats.

5. **Custom Script Commands:**
   - The script engine includes default commands and conditions.
   - It also provides specific commands for interacting with VCS binaries (`bzr`, `fossil`, `git`, `hg`, `svn`).
   - The "handle" command within the script determines which protocol or handler should be used to serve the generated content (e.g., serving as a Git repository, a Subversion repository, etc.).
   - Utility commands like "at" (for setting Git timestamp environment variables) and "unquote" (for unquoting strings) are also available.

6. **Web Interface:**
   - The server provides a web interface:
     - The root path `/` displays a summary of the available scripts and their status (last loaded time, any errors).
     - The `/help` path provides documentation for the script language.

**Inference about Go Language Feature Implementation:**

This code implements a **testing harness** or **mocking framework** specifically designed for testing how the `go` command interacts with different version control systems. It allows developers to simulate various repository setups and behaviors without needing to create and manage real remote repositories for every test case.

**Go Code Example:**

Let's assume we have a script file named `testgit.txt` in the `scriptDir` directory with the following content:

```
# testgit.txt
mkdir repo
cd repo
git init --bare
echo "initial content" > file.txt
git add file.txt
set GIT_COMMITTER_DATE=2023-10-27T10:00:00Z
set GIT_AUTHOR_DATE=2023-10-27T10:00:00Z
git commit -m "Initial commit"
git update-server-info
handle git
```

Now, let's see how the `vcweb` server would be used and accessed:

```go
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

func main() {
	scriptDir := "testdata" // Assume "testdata" directory contains testgit.txt
	workDir, err := os.MkdirTemp("", "vcweb-test-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(workDir)

	logger := log.New(os.Stdout, "vcweb: ", log.LstdFlags)
	server, err := NewServer(scriptDir, workDir, logger)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()

	// Start the server on a random port
	go func() {
		err := http.ListenAndServe(":0", server)
		if err != nil && err != http.ErrServerClosed {
			logger.Fatalf("Server error: %v", err)
		}
	}()

	// Find the address the server is listening on
	addr := server.env[0][strings.Index(server.env[0], "=")+1:]
	baseURL := fmt.Sprintf("http://%s", addr)

	// Access the generated Git repository
	repoURL := baseURL + "/testgit" // Corresponds to the script name

	resp, err := http.Get(repoURL + "/info/refs?service=git-upload-pack")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Response from Git repository:")
	fmt.Println(string(content))

	// Access the overview page
	overviewURL := baseURL + "/"
	resp, err = http.Get(overviewURL)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	overviewContent, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\nOverview page:")
	fmt.Println(string(overviewContent))
}
```

**Assumptions for the Example:**

* A directory named `testdata` exists in the same directory as the `main.go` file.
* The `testdata` directory contains the `testgit.txt` script.
* Git is installed on the system.

**Expected Output (Conceptual):**

The output would include:

* **Response from Git repository:** Output similar to what a Git server would return for `/info/refs?service=git-upload-pack`, indicating the Git repository is accessible.
* **Overview page:**  HTML content showing the status of the `testgit.txt` script (likely marked as "ok" if the script executed successfully).

**Command-Line Parameter Handling:**

The provided code snippet doesn't directly handle command-line parameters. However, the comment within the code:

```
// To run a standalone server based on the vcweb engine, use:
//
//	go test cmd/go/internal/vcweb/vcstest -v --port=0
```

suggests that the actual command-line parameter handling happens in a separate test file, likely `vcstest.go` within the same directory.

Based on this, the likely command-line parameter is `--port`.

* **`--port=0`**:  Specifying `--port=0` likely instructs the server to listen on a random available port. The actual port the server is running on would then need to be discovered (as shown in the `go` example above where the address is extracted from the `server.env`).
* **`--port=<some_port_number>`**:  You could also specify a specific port number to run the server on.

**Detailed Explanation of `--port` (Hypothesized based on context):**

When the `vcweb` server is run using the `go test` command with the `--port` flag, it controls the TCP port on which the HTTP server listens for incoming requests.

* If `--port=0` is provided, the operating system automatically assigns an available port, which is useful for avoiding port conflicts, especially in automated testing environments.
* If `--port=<some_port_number>` is provided (e.g., `--port=8080`), the server will attempt to bind to that specific port. If the port is already in use, the server will likely fail to start.

The test suite that uses `vcweb` would then need a way to determine the actual port the server is running on if `--port=0` is used. This is likely done by inspecting the server's address after it starts listening.

**User Errors (Potential):**

1. **Incorrect Script Path:** Users might make mistakes in the URL path, leading to the server not finding the corresponding script file. For example, if the script is named `myrepo.txt` and placed directly in `scriptDir`, accessing it with `/myrepos` would result in a 404 error. The path must precisely match the script's location relative to `scriptDir`.

   **Example:**

   * `scriptDir`: `/path/to/scripts`
   * Script file: `/path/to/scripts/myrepo.txt`
   * Correct URL: `/myrepo`
   * Incorrect URL: `/myrepos`

2. **Script Errors:** If the script contains errors (e.g., invalid commands, incorrect syntax), the server will likely return a 500 Internal Server Error. Users need to carefully debug their scripts. The server logs (if configured) will usually provide details about the script execution failure.

   **Example:** A script with a typo in a Git command:

   ```
   git initt --bare  # Typo: "initt" instead of "init"
   ```

3. **Missing VCS Binaries:** If a script attempts to use a specific VCS (e.g., `git`) but the corresponding binary is not installed on the server's system, the server will likely return a 501 Not Implemented error, indicating that the necessary server component is missing.

   **Example:** A script using `hg` when Mercurial is not installed.

4. **Caching Issues (Less Frequent):** While the caching is generally beneficial, in rare cases, users might make changes to a script and not see the changes reflected immediately if the server hasn't detected the file modification yet. This is less likely due to the hash-based invalidation.

In summary, `vcweb.go` is a crucial component for testing the `go` command's interaction with version control systems by providing a dynamic and configurable way to simulate various repository scenarios.

Prompt: 
```
这是路径为go/src/cmd/go/internal/vcweb/vcweb.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vcweb serves version control repos for testing the go command.
//
// It is loosely derived from golang.org/x/build/vcs-test/vcweb,
// which ran as a service hosted at vcs-test.golang.org.
//
// When a repository URL is first requested, the vcweb [Server] dynamically
// regenerates the repository using a script interpreted by a [script.Engine].
// The script produces the server's contents for a corresponding root URL and
// all subdirectories of that URL, which are then cached: subsequent requests
// for any URL generated by the script will serve the script's previous output
// until the script is modified.
//
// The script engine includes all of the engine's default commands and
// conditions, as well as commands for each supported VCS binary (bzr, fossil,
// git, hg, and svn), a "handle" command that informs the script which protocol
// or handler to use to serve the request, and utilities "at" (which sets
// environment variables for Git timestamps) and "unquote" (which unquotes its
// argument as if it were a Go string literal).
//
// The server's "/" endpoint provides a summary of the available scripts,
// and "/help" provides documentation for the script environment.
//
// To run a standalone server based on the vcweb engine, use:
//
//	go test cmd/go/internal/vcweb/vcstest -v --port=0
package vcweb

import (
	"bufio"
	"cmd/internal/script"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

// A Server serves cached, dynamically-generated version control repositories.
type Server struct {
	env    []string
	logger *log.Logger

	scriptDir string
	workDir   string
	homeDir   string // $workdir/home
	engine    *script.Engine

	scriptCache sync.Map // script path → *scriptResult

	vcsHandlers map[string]vcsHandler
}

// A vcsHandler serves repositories over HTTP for a known version-control tool.
type vcsHandler interface {
	Available() bool
	Handler(dir string, env []string, logger *log.Logger) (http.Handler, error)
}

// A scriptResult describes the cached result of executing a vcweb script.
type scriptResult struct {
	mu sync.RWMutex

	hash     [sha256.Size]byte // hash of the script file, for cache invalidation
	hashTime time.Time         // timestamp at which the script was run, for diagnostics

	handler http.Handler // HTTP handler configured by the script
	err     error        // error from executing the script, if any
}

// NewServer returns a Server that generates and serves repositories in workDir
// using the scripts found in scriptDir and its subdirectories.
//
// A request for the path /foo/bar/baz will be handled by the first script along
// that path that exists: $scriptDir/foo.txt, $scriptDir/foo/bar.txt, or
// $scriptDir/foo/bar/baz.txt.
func NewServer(scriptDir, workDir string, logger *log.Logger) (*Server, error) {
	if scriptDir == "" {
		panic("vcweb.NewServer: scriptDir is required")
	}
	var err error
	scriptDir, err = filepath.Abs(scriptDir)
	if err != nil {
		return nil, err
	}

	if workDir == "" {
		workDir, err = os.MkdirTemp("", "vcweb-*")
		if err != nil {
			return nil, err
		}
		logger.Printf("vcweb work directory: %s", workDir)
	} else {
		workDir, err = filepath.Abs(workDir)
		if err != nil {
			return nil, err
		}
	}

	homeDir := filepath.Join(workDir, "home")
	if err := os.MkdirAll(homeDir, 0755); err != nil {
		return nil, err
	}

	env := scriptEnviron(homeDir)

	s := &Server{
		env:       env,
		logger:    logger,
		scriptDir: scriptDir,
		workDir:   workDir,
		homeDir:   homeDir,
		engine:    newScriptEngine(),
		vcsHandlers: map[string]vcsHandler{
			"auth":     new(authHandler),
			"dir":      new(dirHandler),
			"bzr":      new(bzrHandler),
			"fossil":   new(fossilHandler),
			"git":      new(gitHandler),
			"hg":       new(hgHandler),
			"insecure": new(insecureHandler),
			"svn":      &svnHandler{svnRoot: workDir, logger: logger},
		},
	}

	if err := os.WriteFile(filepath.Join(s.homeDir, ".gitconfig"), []byte(gitConfig), 0644); err != nil {
		return nil, err
	}
	gitConfigDir := filepath.Join(s.homeDir, ".config", "git")
	if err := os.MkdirAll(gitConfigDir, 0755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(gitConfigDir, "ignore"), []byte(""), 0644); err != nil {
		return nil, err
	}

	if err := os.WriteFile(filepath.Join(s.homeDir, ".hgrc"), []byte(hgrc), 0644); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Server) Close() error {
	var firstErr error
	for _, h := range s.vcsHandlers {
		if c, ok := h.(io.Closer); ok {
			if closeErr := c.Close(); firstErr == nil {
				firstErr = closeErr
			}
		}
	}
	return firstErr
}

// gitConfig contains a ~/.gitconfg file that attempts to provide
// deterministic, platform-agnostic behavior for the 'git' command.
var gitConfig = `
[user]
	name = Go Gopher
	email = gopher@golang.org
[init]
	defaultBranch = main
[core]
	eol = lf
[gui]
	encoding = utf-8
`[1:]

// hgrc contains a ~/.hgrc file that attempts to provide
// deterministic, platform-agnostic behavior for the 'hg' command.
var hgrc = `
[ui]
username=Go Gopher <gopher@golang.org>
[phases]
new-commit=public
[extensions]
convert=
`[1:]

// ServeHTTP implements [http.Handler] for version-control repositories.
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.logger.Printf("serving %s", req.URL)

	defer func() {
		if v := recover(); v != nil {
			debug.PrintStack()
			s.logger.Fatal(v)
		}
	}()

	urlPath := req.URL.Path
	if !strings.HasPrefix(urlPath, "/") {
		urlPath = "/" + urlPath
	}
	clean := path.Clean(urlPath)[1:]
	if clean == "" {
		s.overview(w, req)
		return
	}
	if clean == "help" {
		s.help(w, req)
		return
	}

	// Locate the script that generates the requested path.
	// We follow directories all the way to the end, then look for a ".txt" file
	// matching the first component that doesn't exist. That guarantees
	// uniqueness: if a path exists as a directory, then it cannot exist as a
	// ".txt" script (because the search would ignore that file).
	scriptPath := "."
	for _, part := range strings.Split(clean, "/") {
		scriptPath = filepath.Join(scriptPath, part)
		dir := filepath.Join(s.scriptDir, scriptPath)
		if _, err := os.Stat(dir); err != nil {
			if !os.IsNotExist(err) {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// scriptPath does not exist as a directory, so it either is the script
			// location or the script doesn't exist.
			break
		}
	}
	scriptPath += ".txt"

	err := s.HandleScript(scriptPath, s.logger, func(handler http.Handler) {
		handler.ServeHTTP(w, req)
	})
	if err != nil {
		s.logger.Print(err)
		if notFound := (ScriptNotFoundError{}); errors.As(err, &notFound) {
			http.NotFound(w, req)
		} else if notInstalled := (ServerNotInstalledError{}); errors.As(err, &notInstalled) || errors.Is(err, exec.ErrNotFound) {
			http.Error(w, err.Error(), http.StatusNotImplemented)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// A ScriptNotFoundError indicates that the requested script file does not exist.
// (It typically wraps a "stat" error for the script file.)
type ScriptNotFoundError struct{ err error }

func (e ScriptNotFoundError) Error() string { return e.err.Error() }
func (e ScriptNotFoundError) Unwrap() error { return e.err }

// A ServerNotInstalledError indicates that the server binary required for the
// indicated VCS does not exist.
type ServerNotInstalledError struct{ name string }

func (v ServerNotInstalledError) Error() string {
	return fmt.Sprintf("server for %#q VCS is not installed", v.name)
}

// HandleScript ensures that the script at scriptRelPath has been evaluated
// with its current contents.
//
// If the script completed successfully, HandleScript invokes f on the handler
// with the script's result still read-locked, and waits for it to return. (That
// ensures that cache invalidation does not race with an in-flight handler.)
//
// Otherwise, HandleScript returns the (cached) error from executing the script.
func (s *Server) HandleScript(scriptRelPath string, logger *log.Logger, f func(http.Handler)) error {
	ri, ok := s.scriptCache.Load(scriptRelPath)
	if !ok {
		ri, _ = s.scriptCache.LoadOrStore(scriptRelPath, new(scriptResult))
	}
	r := ri.(*scriptResult)

	relDir := strings.TrimSuffix(scriptRelPath, filepath.Ext(scriptRelPath))
	workDir := filepath.Join(s.workDir, relDir)
	prefix := path.Join("/", filepath.ToSlash(relDir))

	r.mu.RLock()
	defer r.mu.RUnlock()
	for {
		// For efficiency, we cache the script's output (in the work directory)
		// across invocations. However, to allow for rapid iteration, we hash the
		// script's contents and regenerate its output if the contents change.
		//
		// That way, one can use 'go run main.go' in this directory to stand up a
		// server and see the output of the test script in order to fine-tune it.
		content, err := os.ReadFile(filepath.Join(s.scriptDir, scriptRelPath))
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			return ScriptNotFoundError{err}
		}

		hash := sha256.Sum256(content)
		if prevHash := r.hash; prevHash != hash {
			// The script's hash has changed, so regenerate its output.
			func() {
				r.mu.RUnlock()
				r.mu.Lock()
				defer func() {
					r.mu.Unlock()
					r.mu.RLock()
				}()
				if r.hash != prevHash {
					// The cached result changed while we were waiting on the lock.
					// It may have been updated to our hash or something even newer,
					// so don't overwrite it.
					return
				}

				r.hash = hash
				r.hashTime = time.Now()
				r.handler, r.err = nil, nil

				if err := os.RemoveAll(workDir); err != nil {
					r.err = err
					return
				}

				// Note: we use context.Background here instead of req.Context() so that we
				// don't cache a spurious error (and lose work) if the request is canceled
				// while the script is still running.
				scriptHandler, err := s.loadScript(context.Background(), logger, scriptRelPath, content, workDir)
				if err != nil {
					r.err = err
					return
				}
				r.handler = http.StripPrefix(prefix, scriptHandler)
			}()
		}

		if r.hash != hash {
			continue // Raced with an update from another handler; try again.
		}

		if r.err != nil {
			return r.err
		}
		f(r.handler)
		return nil
	}
}

// overview serves an HTML summary of the status of the scripts in the server's
// script directory.
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html>\n")
	fmt.Fprintf(w, "<title>vcweb</title>\n<pre>\n")
	fmt.Fprintf(w, "<b>vcweb</b>\n\n")
	fmt.Fprintf(w, "This server serves various version control repos for testing the go command.\n\n")
	fmt.Fprintf(w, "For an overview of the script language, see <a href=\"/help\">/help</a>.\n\n")

	fmt.Fprintf(w, "<b>cache</b>\n")

	tw := tabwriter.NewWriter(w, 1, 8, 1, '\t', 0)
	err := filepath.WalkDir(s.scriptDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(path) != ".txt" {
			return nil
		}

		rel, err := filepath.Rel(s.scriptDir, path)
		if err != nil {
			return err
		}
		hashTime := "(not loaded)"
		status := ""
		if ri, ok := s.scriptCache.Load(rel); ok {
			r := ri.(*scriptResult)
			r.mu.RLock()
			defer r.mu.RUnlock()

			if !r.hashTime.IsZero() {
				hashTime = r.hashTime.Format(time.RFC3339)
			}
			if r.err == nil {
				status = "ok"
			} else {
				status = r.err.Error()
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", rel, hashTime, status)
		return nil
	})
	tw.Flush()

	if err != nil {
		fmt.Fprintln(w, err)
	}
}

// help serves a plain-text summary of the server's supported script language.
func (s *Server) help(w http.ResponseWriter, req *http.Request) {
	st, err := s.newState(req.Context(), s.workDir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	scriptLog := new(strings.Builder)
	err = s.engine.Execute(st, "help", bufio.NewReader(strings.NewReader("help")), scriptLog)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	io.WriteString(w, scriptLog.String())
}

"""



```