Response: The user wants to understand the functionality of the provided Go code snippet from `go/src/cmd/go/internal/modload/load.go`.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The code is within the `modload` package, specifically `load.go`. This strongly suggests it's related to loading modules and packages in the Go build process.

2. **Analyze individual functions:**  Go through each function in the snippet and determine its role:
    * `resolveMissingImports`:  Deals with adding missing modules to the dependency graph. Key actions involve sorting, updating roots, and handling potential errors.
    * `load`:  Focuses on loading a single package. It retrieves the module graph, resolves the package's location, handles tool dependencies, marks packages as "in all", checks package allowability, scans for imports, and recursively loads dependencies.
    * `pkgTest`:  Manages loading test packages associated with a given package. It ensures the main package's imports are loaded first and then loads the test-specific imports.
    * `stdVendor`:  Determines the canonical import path for packages within the standard library, considering vendor directories within `GOROOT/src`.
    * `computePatternAll`:  Generates a sorted list of all packages marked as `pkgInAll`.
    * `checkMultiplePaths`:  Verifies that a module path isn't used for both itself and as a replacement simultaneously, preventing potential conflicts.
    * `checkTidyCompatibility`:  Checks if package loading would differ between the current module requirements and a specified compatibility version. This is critical for `go mod tidy`'s `-compat` flag and ensuring reproducible builds. It involves comparing module graphs and reporting discrepancies.
    * `scanDir`:  Similar to `imports.ScanDir` but filters out "magic" imports like "C" and legacy "appengine" imports.
    * `buildStacks`:  Constructs import stacks for each package, aiding in error reporting by showing the import path to a particular package.
    * `stackText`:  Formats the import stack into a human-readable string for error messages.
    * `why`:  Generates a simplified import stack for `go mod why`.
    * `Why`:  Exposes the `why` functionality for a given package path.
    * `WhyDepth`:  Returns the depth of the import stack for a given package path.

3. **Infer the overall Go feature:** Based on the functions and their interactions, the code is central to the **module-aware package loading** process in Go. This includes resolving dependencies, handling versions, and ensuring consistency.

4. **Create illustrative Go code examples:**  For key functionalities, craft concise Go code snippets demonstrating their use (even if the internal functions aren't directly called by user code). Focus on the observable effects. Examples should have clear inputs, expected outputs, and context.
    * `resolveMissingImports`:  Illustrate the scenario of a missing indirect dependency being added.
    * `load`: Show how importing a package can trigger the loading of its dependencies.
    * `pkgTest`: Demonstrate loading a test package.
    * `stdVendor`: Showcase how standard library imports are resolved.
    * `checkTidyCompatibility`:  Give an example of how a dependency change can be flagged as incompatible.

5. **Explain command-line parameters:** Identify functions that directly relate to command-line flags (`checkTidyCompatibility` and its `-compat` flag) and provide details on their usage and impact.

6. **Identify potential user errors:** Think about common mistakes developers make with Go modules that relate to the code's functionality.
    * Incorrect `replace` directives leading to `checkMultiplePaths` errors.
    * Inconsistencies between Go versions causing issues flagged by `checkTidyCompatibility`.

7. **Summarize the functionality:**  Provide a concise overview of the entire code snippet's purpose and its contribution to the Go module system. Emphasize the key aspects like dependency resolution, package loading, consistency checks, and error reporting.

8. **Structure the answer:** Organize the information logically with clear headings and subheadings. Use code blocks for examples and format the output for readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on individual function descriptions.
* **Correction:** Realize the need to synthesize the individual functions into a higher-level understanding of the Go feature being implemented.
* **Initial thought:**  Provide only function signatures.
* **Correction:**  Include illustrative Go code examples to make the functionality clearer.
* **Initial thought:** Briefly mention command-line flags.
* **Correction:** Elaborate on the purpose and implications of relevant command-line flags, especially `-compat`.
* **Initial thought:**  Only describe the technical aspects.
* **Correction:** Include potential user errors to make the explanation more practical.
* **Initial thought:** Provide a very detailed and technical summary.
* **Correction:**  Write a more concise and user-friendly summary that captures the essence of the code.
这是对 `go/src/cmd/go/internal/modload/load.go` 文件中一部分代码的功能进行总结和解释。这段代码主要负责 Go 模块加载过程中的核心任务：**加载和解析 Go 包，并维护模块依赖关系图**。

以下是这段代码的具体功能分解：

**1. `resolveMissingImports(ctx context.Context, need map[module.Version]bool) bool`:**

* **功能:**  负责解析和添加缺失的根依赖模块到当前的模块图中。当构建过程发现需要某个根依赖模块但当前模块图中不存在时，此函数会被调用。
* **工作流程:**
    1. 接收一个 `need` 的 map，其中包含了需要添加的缺失的根依赖模块及其版本。
    2. 对 `need` 中的模块进行排序。
    3. 调用 `updateRoots` 函数，尝试将这些缺失的模块添加到模块图中。`updateRoots` 函数会处理模块的下载、解析 `go.mod` 文件等操作。
    4. 检查 `updateRoots` 的执行结果。如果添加失败，会记录错误并可能导致程序退出。
    5. 如果添加成功，会更新 `ld.requirements`，其中包含了最新的模块依赖关系信息。
    6. 如果添加操作没有对根依赖模块产生任何影响（这通常不应该发生），会触发 panic。
* **代码推理示例:**
    ```go
    // 假设 ld.requirements.direct 当前为空，need 中包含了需要添加的模块 "example.com/indirect@v1.0.0"
    need := map[module.Version]bool{
        {Path: "example.com/indirect", Version: "v1.0.0"}: true,
    }
    ld := &loader{requirements: &Requirements{direct: []*module.Version{}}}
    ctx := context.Background()

    // 调用 resolveMissingImports
    success := ld.resolveMissingImports(ctx, need)

    // 假设 updateRoots 成功添加了模块
    // 预期输出:
    // success 为 true
    // ld.requirements.direct 将包含 {Path: "example.com/indirect", Version: "v1.0.0"}

    if success {
        fmt.Println("成功添加缺失的根依赖模块")
        for _, mod := range ld.requirements.direct {
            fmt.Printf("添加的模块: %s@%s\n", mod.Path, mod.Version)
        }
    } else {
        fmt.Println("添加缺失的根依赖模块失败")
    }
    ```
* **假设的输入与输出:**
    * **输入:** `need = map[module.Version]bool{{Path: "example.com/missing", Version: "v1.2.3"}: true}`， `ld.requirements.direct` 为空。
    * **输出:** 如果 `updateRoots` 成功，`ld.requirements.direct` 将包含指向 `example.com/missing@v1.2.3` 的 `module.Version` 指针，函数返回 `true`。如果失败，函数返回 `false`，并且 `ld` 中会记录错误。

**2. `load(ctx context.Context, pkg *loadPkg)`:**

* **功能:**  加载单个 Go 包的信息，包括其依赖关系。
* **工作流程:**
    1. 获取当前的模块图 `mg`，如果启用了模块图裁剪，则可能需要先加载完整的模块图。
    2. 调用 `importFromModules` 函数，从模块图中解析包的模块信息、文件路径等。
    3. 处理 `MainModules.Tools()` 返回的工具包，这些包始终属于 "all" 构建上下文。
    4. 如果包来自主模块，则将其标记为 "all"。
    5. 如果设置了 `ld.AllowPackage` 函数，则调用该函数进行额外的包访问控制。
    6. 判断包是否属于标准库。
    7. 调用 `scanDir` 函数扫描包目录，获取其导入的包列表和测试导入的包列表。
    8. 递归调用 `ld.pkg` 加载当前包导入的依赖包。
    9. 标记当前包的导入已加载完成。
* **代码推理示例:**
    ```go
    // 假设要加载的包路径为 "example.com/mypackage"
    pkg := &loadPkg{path: "example.com/mypackage"}
    ld := &loader{requirements: &Requirements{}}
    ctx := context.Background()

    // 调用 load 函数
    ld.load(ctx, pkg)

    // 预期输出:
    // pkg.mod 将包含 example.com/mypackage 所在的模块信息
    // pkg.dir 将包含包的目录路径
    // pkg.imports 将包含该包导入的其他 loadPkg 指针
    // pkg.err 可能包含加载过程中遇到的错误
    if pkg.err != nil {
        fmt.Printf("加载包 %s 失败: %v\n", pkg.path, pkg.err)
    } else {
        fmt.Printf("成功加载包 %s，位于模块: %s\n", pkg.path, pkg.mod.Path)
        fmt.Printf("包的导入: %v\n", pkg.imports)
    }
    ```
* **假设的输入与输出:**
    * **输入:** `pkg = &loadPkg{path: "fmt"}` (标准库的 `fmt` 包)，`ld.requirements` 已初始化。
    * **输出:** `pkg.mod` 可能为空或指向标准库的虚拟模块，`pkg.dir` 将是 `GOROOT/src/fmt` 的路径，`pkg.imports` 将包含 `fmt` 包导入的其他标准库包的 `loadPkg` 指针，`pkg.err` 为 `nil`。

**3. `pkgTest(ctx context.Context, pkg *loadPkg, testFlags loadPkgFlags) *loadPkg`:**

* **功能:**  加载指定包的测试包的信息。
* **工作流程:**
    1. 确保传入的 `pkg` 不是测试包本身。
    2. 使用 `sync.Once` 确保测试包信息只被创建和加载一次。
    3. 创建一个新的 `loadPkg` 实例作为测试包，并关联到原始的 `pkg`。
    4. 递归调用 `ld.pkg` 加载测试包导入的依赖包。
    5. 标记测试包的导入已加载完成。
* **代码推理示例:**
    ```go
    // 假设已经加载了包 "example.com/mypackage"
    pkg := &loadPkg{path: "example.com/mypackage", flags: pkgImportsLoaded}
    ld := &loader{}
    ctx := context.Background()

    // 调用 pkgTest 加载测试包
    testPkg := ld.pkgTest(ctx, pkg, 0)

    // 预期输出:
    // testPkg.path 将是 "example.com/mypackage"
    // testPkg.testOf 将指向原始的 pkg
    // testPkg.imports 将包含测试文件中导入的其他 loadPkg 指针
    if testPkg != nil {
        fmt.Printf("成功加载测试包 %s\n", testPkg.path)
        fmt.Printf("测试包的导入: %v\n", testPkg.imports)
    }
    ```
* **假设的输入与输出:**
    * **输入:** `pkg = &loadPkg{path: "net/http", flags: pkgImportsLoaded}`，`ld` 已初始化。
    * **输出:** 返回的 `testPkg` 的 `path` 将是 "net/http"，`testPkg.testOf` 指向 `pkg`，`testPkg.imports` 将包含 `net/http` 测试文件中导入的包的 `loadPkg` 指针。

**4. `stdVendor(parentPath, path string) string`:**

* **功能:**  确定标准库包导入路径的规范形式，考虑到 `vendor` 目录。
* **工作流程:**
    1. 检查是否为 FIPS 140 相关的导入。
    2. 如果导入路径是标准库路径，则直接返回。
    3. 如果父包在 `cmd` 目录下，且未禁用 `VendorModulesInGOROOTSrc` 或主模块不是 `cmd`，则尝试查找 `cmd/vendor/path`。
    4. 如果父包不在 `std` 模块内，或者禁用了 `VendorModulesInGOROOTSrc`，或者父包路径以 `vendor/` 开头，则尝试查找 `vendor/path`。
    5. 如果以上情况都不满足，则认为是非 vendor 的模块导入路径。
* **代码推理示例:**
    ```go
    ld := &loader{}
    parentPath := "cmd/go"
    importPath := "fmt"

    canonicalPath := ld.stdVendor(parentPath, importPath)
    // 预期输出: canonicalPath 将是 "fmt"

    parentPath = "net/http"
    importPath = "vendor/example.com/foo"
    canonicalPath = ld.stdVendor(parentPath, importPath)
    // 预期输出: canonicalPath 将是 "vendor/example.com/foo" (如果 GOROOT/src/vendor/example.com/foo 存在)
    ```
* **假设的输入与输出:**
    * **输入:** `parentPath = "net/http"`, `path = "io"`。
    * **输出:** `"io"` (因为 `io` 是标准库，且通常不 vendor 在 `net/http` 中)。
    * **输入:** `parentPath = "cmd/go"`, `path = "golang.org/x/text/unicode/bidi"`。
    * **输出:** `"cmd/vendor/golang.org/x/text/unicode/bidi"` (如果 `GOROOT/src/cmd/vendor/golang.org/x/text/unicode/bidi` 存在)。

**5. `computePatternAll() (all []string)`:**

* **功能:**  计算匹配 "all" 模式的所有包的导入路径列表。
* **工作流程:**
    1. 遍历所有已加载的包 (`ld.pkgs`)。
    2. 如果包被标记为 `pkgInAll` 且不是测试包，则将其路径添加到列表中。
    3. 对列表进行排序。
* **代码推理示例:**
    ```go
    ld := &loader{
        pkgs: []*loadPkg{
            {path: "main", flags: pkgInAll},
            {path: "main_test", flags: pkgInAll}, // 测试包不应该包含在 all 中
            {path: "example.com/lib", flags: pkgInAll},
        },
    }

    allPackages := ld.computePatternAll()
    // 预期输出: allPackages 将是 []string{"example.com/lib", "main"}
    ```
* **假设的输入与输出:**
    * **输入:** `ld.pkgs` 包含多个 `loadPkg`，其中一些标记了 `pkgInAll`。
    * **输出:** 返回一个字符串切片，包含所有标记为 `pkgInAll` 的非测试包的路径，并已排序。

**6. `checkMultiplePaths()`:**

* **功能:**  检查同一个模块路径是否既被用作自身，又被用作另一个模块的替换。
* **工作流程:**
    1. 获取当前的模块列表。
    2. 创建一个 map `firstPath`，用于记录每个源模块第一次出现时的模块路径。
    3. 遍历模块列表，对于每个模块，解析其替换源（如果有）。
    4. 如果一个源模块已经存在于 `firstPath` 中，并且当前的模块路径与之前记录的不同，则报告错误。
* **易犯错的点:**
    * 在 `go.mod` 文件中使用 `replace` 指令时，错误地将一个模块路径既作为自身引入，又作为另一个模块的替换目标。例如：
      ```
      module example.com/main

      require example.com/lib v1.0.0

      replace example.com/lib => ./mylib
      replace example.com/mylib => ../otherlib
      ```
      这里 `example.com/mylib` 既被用作替换目标，也可能被间接依赖引入。
* **代码推理示例:**
    ```go
    ld := &loader{
        requirements: &Requirements{
            rootModules: []*module.Version{
                {Path: "example.com/lib", Version: "v1.0.0"},
                {Path: "example.com/altlib", Version: "v1.0.0"},
            },
        },
    }
    ld.requirements.graph.Store(&ModuleGraphData{
        mg: NewGraph(map[string]string{
            "example.com/lib":    "v1.0.0",
            "example.com/altlib": "v1.0.0",
        }, []*module.Version{
            {Path: "example.com/lib", Version: "v1.0.0"},
            {Path: "example.com/altlib", Version: "v1.0.0"},
        }, map[module.Version]module.Version{
            {Path: "example.com/lib", Version: "v1.0.0"}: {Path: "example.com/mylib", Version: "v1.0.0"},
        }),
    })

    // 假设 ld.requirements.rootModules 中也包含了 example.com/mylib
    ld.requirements.rootModules = append(ld.requirements.rootModules, &module.Version{Path: "example.com/mylib", Version: "v1.0.0"})

    // 调用 checkMultiplePaths
    ld.checkMultiplePaths()

    // 预期输出: 如果 example.com/mylib 也被直接 require，则会输出错误信息，
    // 指出 example.com/mylib 被用于两个不同的模块路径。
    ```

**7. `checkTidyCompatibility(ctx context.Context, rs *Requirements, compatVersion string)`:**

* **功能:**  检查在指定的兼容性 Go 版本下，包的加载结果是否与当前的模块需求一致。这主要用于 `go mod tidy -compat` 命令。
* **工作流程:**
    1. 获取指定兼容性版本的模块图。
    2. 并行地重新解析所有已加载的包，使用兼容性版本的模块图。
    3. 比较在当前版本和兼容性版本下，每个包解析到的模块是否相同。
    4. 如果发现差异，则输出错误信息，提示用户可能需要升级 Go 版本或调整依赖。
* **命令行参数处理:**
    * 该函数主要与 `go mod tidy` 命令的 `-compat` 标志相关。`-compat=go1.16` 会调用此函数，并传入 `rs` 为使用 Go 1.16 语义解析出的模块需求，`compatVersion` 为 "go1.16"。
* **易犯错的点:**
    * 当从较新的 Go 版本降级到较旧的 Go 版本时，可能会遇到兼容性问题，因为较新的版本可能引入了新的模块版本或依赖关系，而较旧的版本无法正确处理。
* **代码推理示例:**
    ```go
    // 假设当前 Go 版本加载了 example.com/lib@v1.1.0，但在 go1.16 下会加载 example.com/lib@v1.0.0
    ld := &loader{
        pkgs: []*loadPkg{{path: "app", mod: module.Version{Path: "example.com/lib", Version: "v1.1.0"}}},
        requirements: &Requirements{/* ... current requirements ... */},
    }
    ctx := context.Background()
    rsCompat := &Requirements{/* ... requirements as per go1.16 ... */}

    // 模拟 rsCompat 下 app 包会加载 example.com/lib@v1.0.0
    rsCompat.graph.Store(&ModuleGraphData{
        m: map[string]string{"example.com/lib": "v1.0.0"},
    })

    // 调用 checkTidyCompatibility
    ld.checkTidyCompatibility(ctx, rsCompat, "go1.16")

    // 预期输出: 会输出错误信息，指出 "app" 包在当前版本加载自 example.com/lib@v1.1.0，
    // 但在 go1.16 下会加载自 example.com/lib@v1.0.0。
    ```

**8. `scanDir(modroot string, dir string, tags map[string]bool) (imports_, testImports []string, err error)`:**

* **功能:**  扫描指定目录下的 Go 代码文件，解析其导入的包列表和测试导入的包列表，并过滤掉一些特殊的 "magic" 导入。
* **工作流程:**
    1. 尝试从模块索引中获取包信息，如果找到则使用模块索引的扫描功能。
    2. 否则，使用标准的 `imports.ScanDir` 函数进行扫描。
    3. 过滤掉 "C"、"appengine" 等特殊导入。
* **代码推理示例:**
    ```go
    // 假设 dir 指向一个包含以下代码的 Go 文件：
    // package main
    // import "fmt"
    // import "C"
    // import "example.com/mylib"

    modroot := "example.com/myproject"
    dir := "/path/to/mypackage"
    tags := map[string]bool{}
    imports, _, err := scanDir(modroot, dir, tags)

    // 预期输出: imports 将是 []string{"fmt", "example.com/mylib"}，"C" 被过滤掉了。
    ```
* **假设的输入与输出:**
    * **输入:** `modroot = ""`, `dir = "/path/to/mypkg"`, `tags = nil`。假设 `/path/to/mypkg` 下的 Go 文件导入了 `"os"` 和 `"unsafe"`。
    * **输出:** `imports_ = []string{"os", "unsafe"}`，`testImports = nil`，`err = nil`。

**9. `buildStacks()`:**

* **功能:**  为每个已加载的包构建最小导入堆栈，用于在错误消息中展示导入路径。
* **工作流程:**
    1. 初始化 `ld.pkgs` 列表，并将根包添加到列表中，并设置其 `stack` 字段为自身作为哨兵。
    2. 遍历 `ld.pkgs`，对于每个包，遍历其导入的依赖包和测试依赖包。
    3. 如果依赖包的 `stack` 字段为空，则将其设置为当前包，并将依赖包添加到 `ld.pkgs` 中。
    4. 清除根包的 `stack` 字段。
* **代码推理示例:**
    ```go
    ld := &loader{
        roots: []*loadPkg{{path: "main"}},
        pkgs:  []*loadPkg{},
    }
    mainPkg := ld.roots[0]
    mainPkg.imports = []*loadPkg{{path: "example.com/a"}}
    aPkg := mainPkg.imports[0]
    aPkg.imports = []*loadPkg{{path: "example.com/b"}}
    bPkg := aPkg.imports[0]

    ld.buildStacks()

    // 预期输出:
    // mainPkg.stack == nil
    // aPkg.stack == mainPkg
    // bPkg.stack == aPkg
    ```

**10. `stackText() string`:**

* **功能:**  生成用于错误报告的包导入堆栈文本。
* **工作流程:**
    1. 从当前包开始，沿着 `stack` 指针向上回溯，构建导入路径的切片。
    2. 格式化输出，显示导入关系，包括测试依赖。
* **代码推理示例:**
    ```go
    pkgB := &loadPkg{path: "example.com/b"}
    pkgA := &loadPkg{path: "example.com/a", imports: []*loadPkg{pkgB}}
    pkgMain := &loadPkg{path: "main", imports: []*loadPkg{pkgA}}
    pkgB.stack = pkgA
    pkgA.stack = pkgMain

    stackText := pkgB.stackText()
    // 预期输出: "main imports\n\texample.com/a imports\n\texample.com/b"
    ```

**11. `why() string`:**

* **功能:**  生成用于 "go mod why" 命令输出的包导入原因文本。
* **工作流程:**
    1. 从当前包开始，沿着 `stack` 指针向上回溯，构建导入路径的切片。
    2. 格式化输出，每行显示一个导入的包。
* **代码推理示例:**
    ```go
    pkgB := &loadPkg{path: "example.com/b"}
    pkgA := &loadPkg{path: "example.com/a", imports: []*loadPkg{pkgB}}
    pkgMain := &loadPkg{path: "main", imports: []*loadPkg{pkgA}}
    pkgB.stack = pkgA
    pkgA.stack = pkgMain

    whyText := pkgB.why()
    // 预期输出: "main\nexample.com/a\nexample.com/b\n"
    ```

**12. `Why(path string) string`:**

* **功能:**  对外暴露的函数，用于获取指定包的 "go mod why" 输出。
* **工作流程:**
    1. 从全局的 `loaded` 变量中获取指定路径的 `loadPkg`。
    2. 如果找到，调用 `why()` 方法获取原因文本。
* **代码推理:**  这个函数依赖于包加载过程已经完成，并将加载的包信息缓存到 `loaded.pkgCache` 中。

**13. `WhyDepth(path string) int`:**

* **功能:**  对外暴露的函数，用于获取指定包在 "go mod why" 输出中的深度。
* **工作流程:**
    1. 从全局的 `loaded` 变量中获取指定路径的 `loadPkg`。
    2. 如果找到，沿着 `stack` 指针向上计数，计算导入深度。

**总结 `load.go` 的功能 (第2部分):**

这段代码是 Go 模块加载机制的核心组成部分，主要负责以下功能：

* **解析和添加缺失的根依赖模块到模块图中。** (`resolveMissingImports`)
* **加载单个 Go 包的信息，包括其依赖关系，并处理标准库和 vendor 目录。** (`load`, `pkgTest`, `stdVendor`)
* **计算匹配 "all" 构建模式的包列表。** (`computePatternAll`)
* **执行模块路径的冲突检查。** (`checkMultiplePaths`)
* **进行跨 Go 版本兼容性检查，用于 `go mod tidy -compat`。** (`checkTidyCompatibility`)
* **扫描 Go 代码目录，解析导入的包列表，并过滤特殊导入。** (`scanDir`)
* **构建包的导入堆栈，用于错误报告和 "go mod why" 命令。** (`buildStacks`, `stackText`, `why`, `Why`, `WhyDepth`)

总而言之，这段代码实现了 Go 模块系统中加载和管理包及其依赖关系的关键逻辑，确保了构建过程能够正确地找到并使用所需的代码。

### 提示词
```
这是路径为go/src/cmd/go/internal/modload/load.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
}

	toAdd := make([]module.Version, 0, len(need))
	for m := range need {
		toAdd = append(toAdd, m)
	}
	gover.ModSort(toAdd)

	rs, err := updateRoots(ctx, ld.requirements.direct, ld.requirements, nil, toAdd, ld.AssumeRootsImported)
	if err != nil {
		// We are missing some root dependency, and for some reason we can't load
		// enough of the module dependency graph to add the missing root. Package
		// loading is doomed to fail, so fail quickly.
		ld.error(err)
		ld.exitIfErrors(ctx)
		return false
	}
	if slices.Equal(rs.rootModules, ld.requirements.rootModules) {
		// Something is deeply wrong. resolveMissingImports gave us a non-empty
		// set of modules to add to the graph, but adding those modules had no
		// effect — either they were already in the graph, or updateRoots did not
		// add them as requested.
		panic(fmt.Sprintf("internal error: adding %v to module graph had no effect on root requirements (%v)", toAdd, rs.rootModules))
	}

	ld.requirements = rs
	return true
}

// load loads an individual package.
func (ld *loader) load(ctx context.Context, pkg *loadPkg) {
	var mg *ModuleGraph
	if ld.requirements.pruning == unpruned {
		var err error
		mg, err = ld.requirements.Graph(ctx)
		if err != nil {
			// We already checked the error from Graph in loadFromRoots and/or
			// updateRequirements, so we ignored the error on purpose and we should
			// keep trying to push past it.
			//
			// However, because mg may be incomplete (and thus may select inaccurate
			// versions), we shouldn't use it to load packages. Instead, we pass a nil
			// *ModuleGraph, which will cause mg to first try loading from only the
			// main module and root dependencies.
			mg = nil
		}
	}

	var modroot string
	pkg.mod, modroot, pkg.dir, pkg.altMods, pkg.err = importFromModules(ctx, pkg.path, ld.requirements, mg, ld.skipImportModFiles)
	if MainModules.Tools()[pkg.path] {
		// Tools declared by main modules are always in "all".
		// We apply the package flags before returning so that missing
		// tool dependencies report an error https://go.dev/issue/70582
		ld.applyPkgFlags(ctx, pkg, pkgInAll)
	}
	if pkg.dir == "" {
		return
	}
	if MainModules.Contains(pkg.mod.Path) {
		// Go ahead and mark pkg as in "all". This provides the invariant that a
		// package that is *only* imported by other packages in "all" is always
		// marked as such before loading its imports.
		//
		// We don't actually rely on that invariant at the moment, but it may
		// improve efficiency somewhat and makes the behavior a bit easier to reason
		// about (by reducing churn on the flag bits of dependencies), and costs
		// essentially nothing (these atomic flag ops are essentially free compared
		// to scanning source code for imports).
		ld.applyPkgFlags(ctx, pkg, pkgInAll)
	}
	if ld.AllowPackage != nil {
		if err := ld.AllowPackage(ctx, pkg.path, pkg.mod); err != nil {
			pkg.err = err
		}
	}

	pkg.inStd = (search.IsStandardImportPath(pkg.path) && search.InDir(pkg.dir, cfg.GOROOTsrc) != "")

	var imports, testImports []string

	if cfg.BuildContext.Compiler == "gccgo" && pkg.inStd {
		// We can't scan standard packages for gccgo.
	} else {
		var err error
		imports, testImports, err = scanDir(modroot, pkg.dir, ld.Tags)
		if err != nil {
			pkg.err = err
			return
		}
	}

	pkg.imports = make([]*loadPkg, 0, len(imports))
	var importFlags loadPkgFlags
	if pkg.flags.has(pkgInAll) {
		importFlags = pkgInAll
	}
	for _, path := range imports {
		if pkg.inStd {
			// Imports from packages in "std" and "cmd" should resolve using
			// GOROOT/src/vendor even when "std" is not the main module.
			path = ld.stdVendor(pkg.path, path)
		}
		pkg.imports = append(pkg.imports, ld.pkg(ctx, path, importFlags))
	}
	pkg.testImports = testImports

	ld.applyPkgFlags(ctx, pkg, pkgImportsLoaded)
}

// pkgTest locates the test of pkg, creating it if needed, and updates its state
// to reflect the given flags.
//
// pkgTest requires that the imports of pkg have already been loaded (flagged
// with pkgImportsLoaded).
func (ld *loader) pkgTest(ctx context.Context, pkg *loadPkg, testFlags loadPkgFlags) *loadPkg {
	if pkg.isTest() {
		panic("pkgTest called on a test package")
	}

	createdTest := false
	pkg.testOnce.Do(func() {
		pkg.test = &loadPkg{
			path:   pkg.path,
			testOf: pkg,
			mod:    pkg.mod,
			dir:    pkg.dir,
			err:    pkg.err,
			inStd:  pkg.inStd,
		}
		ld.applyPkgFlags(ctx, pkg.test, testFlags)
		createdTest = true
	})

	test := pkg.test
	if createdTest {
		test.imports = make([]*loadPkg, 0, len(pkg.testImports))
		var importFlags loadPkgFlags
		if test.flags.has(pkgInAll) {
			importFlags = pkgInAll
		}
		for _, path := range pkg.testImports {
			if pkg.inStd {
				path = ld.stdVendor(test.path, path)
			}
			test.imports = append(test.imports, ld.pkg(ctx, path, importFlags))
		}
		pkg.testImports = nil
		ld.applyPkgFlags(ctx, test, pkgImportsLoaded)
	} else {
		ld.applyPkgFlags(ctx, test, testFlags)
	}

	return test
}

// stdVendor returns the canonical import path for the package with the given
// path when imported from the standard-library package at parentPath.
func (ld *loader) stdVendor(parentPath, path string) string {
	if p, _, ok := fips140.ResolveImport(path); ok {
		return p
	}
	if search.IsStandardImportPath(path) {
		return path
	}

	if str.HasPathPrefix(parentPath, "cmd") {
		if !ld.VendorModulesInGOROOTSrc || !MainModules.Contains("cmd") {
			vendorPath := pathpkg.Join("cmd", "vendor", path)

			if _, err := os.Stat(filepath.Join(cfg.GOROOTsrc, filepath.FromSlash(vendorPath))); err == nil {
				return vendorPath
			}
		}
	} else if !ld.VendorModulesInGOROOTSrc || !MainModules.Contains("std") || str.HasPathPrefix(parentPath, "vendor") {
		// If we are outside of the 'std' module, resolve imports from within 'std'
		// to the vendor directory.
		//
		// Do the same for importers beginning with the prefix 'vendor/' even if we
		// are *inside* of the 'std' module: the 'vendor/' packages that resolve
		// globally from GOROOT/src/vendor (and are listed as part of 'go list std')
		// are distinct from the real module dependencies, and cannot import
		// internal packages from the real module.
		//
		// (Note that although the 'vendor/' packages match the 'std' *package*
		// pattern, they are not part of the std *module*, and do not affect
		// 'go mod tidy' and similar module commands when working within std.)
		vendorPath := pathpkg.Join("vendor", path)
		if _, err := os.Stat(filepath.Join(cfg.GOROOTsrc, filepath.FromSlash(vendorPath))); err == nil {
			return vendorPath
		}
	}

	// Not vendored: resolve from modules.
	return path
}

// computePatternAll returns the list of packages matching pattern "all",
// starting with a list of the import paths for the packages in the main module.
func (ld *loader) computePatternAll() (all []string) {
	for _, pkg := range ld.pkgs {
		if pkg.flags.has(pkgInAll) && !pkg.isTest() {
			all = append(all, pkg.path)
		}
	}
	sort.Strings(all)
	return all
}

// checkMultiplePaths verifies that a given module path is used as itself
// or as a replacement for another module, but not both at the same time.
//
// (See https://golang.org/issue/26607 and https://golang.org/issue/34650.)
func (ld *loader) checkMultiplePaths() {
	mods := ld.requirements.rootModules
	if cached := ld.requirements.graph.Load(); cached != nil {
		if mg := cached.mg; mg != nil {
			mods = mg.BuildList()
		}
	}

	firstPath := map[module.Version]string{}
	for _, mod := range mods {
		src := resolveReplacement(mod)
		if prev, ok := firstPath[src]; !ok {
			firstPath[src] = mod.Path
		} else if prev != mod.Path {
			ld.error(fmt.Errorf("%s@%s used for two different module paths (%s and %s)", src.Path, src.Version, prev, mod.Path))
		}
	}
}

// checkTidyCompatibility emits an error if any package would be loaded from a
// different module under rs than under ld.requirements.
func (ld *loader) checkTidyCompatibility(ctx context.Context, rs *Requirements, compatVersion string) {
	goVersion := rs.GoVersion()
	suggestUpgrade := false
	suggestEFlag := false
	suggestFixes := func() {
		if ld.AllowErrors {
			// The user is explicitly ignoring these errors, so don't bother them with
			// other options.
			return
		}

		// We print directly to os.Stderr because this information is advice about
		// how to fix errors, not actually an error itself.
		// (The actual errors should have been logged already.)

		fmt.Fprintln(os.Stderr)

		goFlag := ""
		if goVersion != MainModules.GoVersion() {
			goFlag = " -go=" + goVersion
		}

		compatFlag := ""
		if compatVersion != gover.Prev(goVersion) {
			compatFlag = " -compat=" + compatVersion
		}
		if suggestUpgrade {
			eDesc := ""
			eFlag := ""
			if suggestEFlag {
				eDesc = ", leaving some packages unresolved"
				eFlag = " -e"
			}
			fmt.Fprintf(os.Stderr, "To upgrade to the versions selected by go %s%s:\n\tgo mod tidy%s -go=%s && go mod tidy%s -go=%s%s\n", compatVersion, eDesc, eFlag, compatVersion, eFlag, goVersion, compatFlag)
		} else if suggestEFlag {
			// If some packages are missing but no package is upgraded, then we
			// shouldn't suggest upgrading to the Go 1.16 versions explicitly — that
			// wouldn't actually fix anything for Go 1.16 users, and *would* break
			// something for Go 1.17 users.
			fmt.Fprintf(os.Stderr, "To proceed despite packages unresolved in go %s:\n\tgo mod tidy -e%s%s\n", compatVersion, goFlag, compatFlag)
		}

		fmt.Fprintf(os.Stderr, "If reproducibility with go %s is not needed:\n\tgo mod tidy%s -compat=%s\n", compatVersion, goFlag, goVersion)

		// TODO(#46141): Populate the linked wiki page.
		fmt.Fprintf(os.Stderr, "For other options, see:\n\thttps://golang.org/doc/modules/pruning\n")
	}

	mg, err := rs.Graph(ctx)
	if err != nil {
		ld.error(fmt.Errorf("error loading go %s module graph: %w", compatVersion, err))
		ld.switchIfErrors(ctx)
		suggestFixes()
		ld.exitIfErrors(ctx)
		return
	}

	// Re-resolve packages in parallel.
	//
	// We re-resolve each package — rather than just checking versions — to ensure
	// that we have fetched module source code (and, importantly, checksums for
	// that source code) for all modules that are necessary to ensure that imports
	// are unambiguous. That also produces clearer diagnostics, since we can say
	// exactly what happened to the package if it became ambiguous or disappeared
	// entirely.
	//
	// We re-resolve the packages in parallel because this process involves disk
	// I/O to check for package sources, and because the process of checking for
	// ambiguous imports may require us to download additional modules that are
	// otherwise pruned out in Go 1.17 — we don't want to block progress on other
	// packages while we wait for a single new download.
	type mismatch struct {
		mod module.Version
		err error
	}
	mismatchMu := make(chan map[*loadPkg]mismatch, 1)
	mismatchMu <- map[*loadPkg]mismatch{}
	for _, pkg := range ld.pkgs {
		if pkg.mod.Path == "" && pkg.err == nil {
			// This package is from the standard library (which does not vary based on
			// the module graph).
			continue
		}

		pkg := pkg
		ld.work.Add(func() {
			mod, _, _, _, err := importFromModules(ctx, pkg.path, rs, mg, ld.skipImportModFiles)
			if mod != pkg.mod {
				mismatches := <-mismatchMu
				mismatches[pkg] = mismatch{mod: mod, err: err}
				mismatchMu <- mismatches
			}
		})
	}
	<-ld.work.Idle()

	mismatches := <-mismatchMu
	if len(mismatches) == 0 {
		// Since we're running as part of 'go mod tidy', the roots of the module
		// graph should contain only modules that are relevant to some package in
		// the package graph. We checked every package in the package graph and
		// didn't find any mismatches, so that must mean that all of the roots of
		// the module graph are also consistent.
		//
		// If we're wrong, Go 1.16 in -mod=readonly mode will error out with
		// "updates to go.mod needed", which would be very confusing. So instead,
		// we'll double-check that our reasoning above actually holds — if it
		// doesn't, we'll emit an internal error and hopefully the user will report
		// it as a bug.
		for _, m := range ld.requirements.rootModules {
			if v := mg.Selected(m.Path); v != m.Version {
				fmt.Fprintln(os.Stderr)
				base.Fatalf("go: internal error: failed to diagnose selected-version mismatch for module %s: go %s selects %s, but go %s selects %s\n\tPlease report this at https://golang.org/issue.", m.Path, goVersion, m.Version, compatVersion, v)
			}
		}
		return
	}

	// Iterate over the packages (instead of the mismatches map) to emit errors in
	// deterministic order.
	for _, pkg := range ld.pkgs {
		mismatch, ok := mismatches[pkg]
		if !ok {
			continue
		}

		if pkg.isTest() {
			// We already did (or will) report an error for the package itself,
			// so don't report a duplicate (and more verbose) error for its test.
			if _, ok := mismatches[pkg.testOf]; !ok {
				base.Fatalf("go: internal error: mismatch recorded for test %s, but not its non-test package", pkg.path)
			}
			continue
		}

		switch {
		case mismatch.err != nil:
			// pkg resolved successfully, but errors out using the requirements in rs.
			//
			// This could occur because the import is provided by a single root (and
			// is thus unambiguous in a main module with a pruned module graph) and
			// also one or more transitive dependencies (and is ambiguous with an
			// unpruned graph).
			//
			// It could also occur because some transitive dependency upgrades the
			// module that previously provided the package to a version that no
			// longer does, or to a version for which the module source code (but
			// not the go.mod file in isolation) has a checksum error.
			if missing := (*ImportMissingError)(nil); errors.As(mismatch.err, &missing) {
				selected := module.Version{
					Path:    pkg.mod.Path,
					Version: mg.Selected(pkg.mod.Path),
				}
				ld.error(fmt.Errorf("%s loaded from %v,\n\tbut go %s would fail to locate it in %s", pkg.stackText(), pkg.mod, compatVersion, selected))
			} else {
				if ambiguous := (*AmbiguousImportError)(nil); errors.As(mismatch.err, &ambiguous) {
					// TODO: Is this check needed?
				}
				ld.error(fmt.Errorf("%s loaded from %v,\n\tbut go %s would fail to locate it:\n\t%v", pkg.stackText(), pkg.mod, compatVersion, mismatch.err))
			}

			suggestEFlag = true

			// Even if we press ahead with the '-e' flag, the older version will
			// error out in readonly mode if it thinks the go.mod file contains
			// any *explicit* dependency that is not at its selected version,
			// even if that dependency is not relevant to any package being loaded.
			//
			// We check for that condition here. If all of the roots are consistent
			// the '-e' flag suffices, but otherwise we need to suggest an upgrade.
			if !suggestUpgrade {
				for _, m := range ld.requirements.rootModules {
					if v := mg.Selected(m.Path); v != m.Version {
						suggestUpgrade = true
						break
					}
				}
			}

		case pkg.err != nil:
			// pkg had an error in with a pruned module graph (presumably suppressed
			// with the -e flag), but the error went away using an unpruned graph.
			//
			// This is possible, if, say, the import is unresolved in the pruned graph
			// (because the "latest" version of each candidate module either is
			// unavailable or does not contain the package), but is resolved in the
			// unpruned graph due to a newer-than-latest dependency that is normally
			// pruned out.
			//
			// This could also occur if the source code for the module providing the
			// package in the pruned graph has a checksum error, but the unpruned
			// graph upgrades that module to a version with a correct checksum.
			//
			// pkg.err should have already been logged elsewhere — along with a
			// stack trace — so log only the import path and non-error info here.
			suggestUpgrade = true
			ld.error(fmt.Errorf("%s failed to load from any module,\n\tbut go %s would load it from %v", pkg.path, compatVersion, mismatch.mod))

		case pkg.mod != mismatch.mod:
			// The package is loaded successfully by both Go versions, but from a
			// different module in each. This could lead to subtle (and perhaps even
			// unnoticed!) variations in behavior between builds with different
			// toolchains.
			suggestUpgrade = true
			ld.error(fmt.Errorf("%s loaded from %v,\n\tbut go %s would select %v\n", pkg.stackText(), pkg.mod, compatVersion, mismatch.mod.Version))

		default:
			base.Fatalf("go: internal error: mismatch recorded for package %s, but no differences found", pkg.path)
		}
	}

	ld.switchIfErrors(ctx)
	suggestFixes()
	ld.exitIfErrors(ctx)
}

// scanDir is like imports.ScanDir but elides known magic imports from the list,
// so that we do not go looking for packages that don't really exist.
//
// The standard magic import is "C", for cgo.
//
// The only other known magic imports are appengine and appengine/*.
// These are so old that they predate "go get" and did not use URL-like paths.
// Most code today now uses google.golang.org/appengine instead,
// but not all code has been so updated. When we mostly ignore build tags
// during "go vendor", we look into "// +build appengine" files and
// may see these legacy imports. We drop them so that the module
// search does not look for modules to try to satisfy them.
func scanDir(modroot string, dir string, tags map[string]bool) (imports_, testImports []string, err error) {
	if ip, mierr := modindex.GetPackage(modroot, dir); mierr == nil {
		imports_, testImports, err = ip.ScanDir(tags)
		goto Happy
	} else if !errors.Is(mierr, modindex.ErrNotIndexed) {
		return nil, nil, mierr
	}

	imports_, testImports, err = imports.ScanDir(dir, tags)
Happy:

	filter := func(x []string) []string {
		w := 0
		for _, pkg := range x {
			if pkg != "C" && pkg != "appengine" && !strings.HasPrefix(pkg, "appengine/") &&
				pkg != "appengine_internal" && !strings.HasPrefix(pkg, "appengine_internal/") {
				x[w] = pkg
				w++
			}
		}
		return x[:w]
	}

	return filter(imports_), filter(testImports), err
}

// buildStacks computes minimal import stacks for each package,
// for use in error messages. When it completes, packages that
// are part of the original root set have pkg.stack == nil,
// and other packages have pkg.stack pointing at the next
// package up the import stack in their minimal chain.
// As a side effect, buildStacks also constructs ld.pkgs,
// the list of all packages loaded.
func (ld *loader) buildStacks() {
	if len(ld.pkgs) > 0 {
		panic("buildStacks")
	}
	for _, pkg := range ld.roots {
		pkg.stack = pkg // sentinel to avoid processing in next loop
		ld.pkgs = append(ld.pkgs, pkg)
	}
	for i := 0; i < len(ld.pkgs); i++ { // not range: appending to ld.pkgs in loop
		pkg := ld.pkgs[i]
		for _, next := range pkg.imports {
			if next.stack == nil {
				next.stack = pkg
				ld.pkgs = append(ld.pkgs, next)
			}
		}
		if next := pkg.test; next != nil && next.stack == nil {
			next.stack = pkg
			ld.pkgs = append(ld.pkgs, next)
		}
	}
	for _, pkg := range ld.roots {
		pkg.stack = nil
	}
}

// stackText builds the import stack text to use when
// reporting an error in pkg. It has the general form
//
//	root imports
//		other imports
//		other2 tested by
//		other2.test imports
//		pkg
func (pkg *loadPkg) stackText() string {
	var stack []*loadPkg
	for p := pkg; p != nil; p = p.stack {
		stack = append(stack, p)
	}

	var buf strings.Builder
	for i := len(stack) - 1; i >= 0; i-- {
		p := stack[i]
		fmt.Fprint(&buf, p.path)
		if p.testOf != nil {
			fmt.Fprint(&buf, ".test")
		}
		if i > 0 {
			if stack[i-1].testOf == p {
				fmt.Fprint(&buf, " tested by\n\t")
			} else {
				fmt.Fprint(&buf, " imports\n\t")
			}
		}
	}
	return buf.String()
}

// why returns the text to use in "go mod why" output about the given package.
// It is less ornate than the stackText but contains the same information.
func (pkg *loadPkg) why() string {
	var buf strings.Builder
	var stack []*loadPkg
	for p := pkg; p != nil; p = p.stack {
		stack = append(stack, p)
	}

	for i := len(stack) - 1; i >= 0; i-- {
		p := stack[i]
		if p.testOf != nil {
			fmt.Fprintf(&buf, "%s.test\n", p.testOf.path)
		} else {
			fmt.Fprintf(&buf, "%s\n", p.path)
		}
	}
	return buf.String()
}

// Why returns the "go mod why" output stanza for the given package,
// without the leading # comment.
// The package graph must have been loaded already, usually by LoadPackages.
// If there is no reason for the package to be in the current build,
// Why returns an empty string.
func Why(path string) string {
	pkg, ok := loaded.pkgCache.Get(path)
	if !ok {
		return ""
	}
	return pkg.why()
}

// WhyDepth returns the number of steps in the Why listing.
// If there is no reason for the package to be in the current build,
// WhyDepth returns 0.
func WhyDepth(path string) int {
	n := 0
	pkg, _ := loaded.pkgCache.Get(path)
	for p := pkg; p != nil; p = p.stack {
		n++
	}
	return n
}
```