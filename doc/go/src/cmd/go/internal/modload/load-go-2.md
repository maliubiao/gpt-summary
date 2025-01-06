Response:
The user wants a summary of the Go code provided, focusing on its function within the `go/src/cmd/go/internal/modload/load.go` file. This is the third part of a larger code snippet.

Here's a breakdown of the code's functionality:

1. **Adding missing root dependencies:** The `resolveMissingImports` function attempts to add modules to the dependency graph if imports are missing.
2. **Loading individual packages:** The `load` function is responsible for loading information about a single Go package, including its dependencies.
3. **Handling test packages:** The `pkgTest` function manages the loading and processing of test packages associated with a regular package.
4. **Resolving standard library imports:** The `stdVendor` function determines the correct import path for standard library packages, considering potential vendoring.
5. **Computing the "all" pattern:** The `computePatternAll` function identifies all packages considered part of the "all" pattern.
6. **Checking for conflicting module paths:** The `checkMultiplePaths` function ensures that a module path isn't used both as itself and as a replacement.
7. **Ensuring `go mod tidy` compatibility:** The `checkTidyCompatibility` function verifies that package loading is consistent with a previous Go version, aiding in reproducible builds.
8. **Scanning directories for imports:** The `scanDir` function extracts import statements from Go source files, filtering out special "magic" imports.
9. **Building import stacks:** The `buildStacks` function constructs the import dependency tree, which is helpful for error reporting and `go mod why`.
10. **Generating import stack text:** The `stackText` function formats the import stack into a human-readable string.
11. **Generating "go mod why" output:** The `why` function creates the output for the `go mod why` command for a specific package.
12. **Public API for "go mod why":** The `Why` and `WhyDepth` functions provide a public interface to retrieve the "go mod why" information for a given package path.

Based on this analysis, I can now formulate the final answer.
这是 `go/src/cmd/go/internal/modload/load.go` 文件的第三部分代码，它主要负责 **完成 Go 包的加载过程，并提供与模块依赖相关的兼容性检查和查询功能**。

综合前两部分的功能，我们可以将这部分代码的功能归纳如下：

**核心功能：完成 Go 包的加载和依赖关系构建**

* **解决缺失的根依赖 (resolveMissingImports):**  当发现有根依赖缺失时，尝试将这些缺失的模块添加到模块依赖图中。这确保了项目所需的顶级依赖存在。
* **加载单个包 (load):**  负责加载单个 Go 包的信息，包括它的导入路径、所在目录、所属模块以及依赖的其他包。
    * 它会根据当前的模块图 (`ModuleGraph`) 来解析导入路径。
    * 它会处理由主模块声明的工具包。
    * 它会处理标准库中的包，并考虑 `GOROOT/src/vendor` 的路径。
    * 它会扫描源代码目录来查找当前包的导入依赖。
* **加载测试包 (pkgTest):**  当需要加载某个包的测试时，这个函数会创建或获取对应的测试包，并加载其依赖。
* **标准库 Vendor 处理 (stdVendor):**  当加载标准库中的包时，这个函数负责确定其正确的导入路径，考虑到 `GOROOT/src/vendor` 目录下的 vendor 情况。

**辅助功能：模块兼容性和依赖关系查询**

* **计算 "all" 模式 (computePatternAll):**  计算符合 "all" 模式的所有包（通常指主模块及其所有依赖）。
* **检查多路径冲突 (checkMultiplePaths):**  验证一个模块路径是否只用作自身或者只用作另一个模块的替换，避免混淆。
* **检查与 `go mod tidy` 的兼容性 (checkTidyCompatibility):**  为了保证构建的可重复性，这个函数会检查当前加载的包以及它们的来源模块是否与指定 Go 版本 (`go mod tidy`) 的结果一致。如果存在不一致，会给出提示信息，指导用户如何修复。
* **扫描目录获取导入 (scanDir):**  扫描指定目录下的 Go 源文件，提取出 `import` 语句中的路径。它会过滤掉一些特殊的 "魔法" 导入，例如 "C" 和旧版本的 "appengine"。
* **构建导入栈 (buildStacks):**  构建每个已加载包的导入路径栈，用于在错误信息中显示清晰的依赖链。
* **生成导入栈文本 (stackText):**  将包的导入栈信息格式化成易于阅读的字符串。
* **生成 `go mod why` 输出 (why):**  生成 `go mod why` 命令输出的文本，解释为什么某个包会被包含到构建中。
* **`go mod why` 公共 API (Why, WhyDepth):**  提供公共函数，允许外部查询指定包的 `go mod why` 信息和依赖深度。

**代码示例：加载单个包**

假设我们正在加载名为 `example.com/mypkg` 的包，它依赖于标准库的 `fmt` 和第三方库 `github.com/ BurntSushi/toml`。

**假设输入：**

* `pkg.path`: "example.com/mypkg"
* `ld.requirements`: 包含了项目模块依赖信息的结构体，包括 `github.com/BurntSushi/toml` 的信息。
* `mg`: 当前的模块图。

**可能的 `load` 函数执行过程：**

1. `importFromModules` 函数会根据 `pkg.path` 和 `ld.requirements` 在模块图中查找 `example.com/mypkg` 所在的模块和目录。
2. `scanDir` 函数会扫描 `example.com/mypkg` 的源代码目录，找到导入的 "fmt" 和 "github.com/BurntSushi/toml"。
3. 对于导入的 "fmt"，`ld.pkg` 函数会被调用，由于 "fmt" 是标准库，`stdVendor` 可能会被调用来确定其路径。
4. 对于导入的 "github.com/BurntSushi/toml"，`ld.pkg` 函数会被调用，它会根据 `ld.requirements` 中的信息找到对应的模块和包。
5. 最终，`pkg.imports` 会包含代表 "fmt" 和 "github.com/BurntSushi/toml" 的 `loadPkg` 结构体。

**易犯错的点：与 `go mod tidy` 的兼容性**

开发者可能在不同的 Go 版本下构建项目，导致 `go.mod` 文件中的依赖与实际使用的依赖不一致。这会导致使用旧版本 Go 构建时出现问题。

**示例：**

假设你在 Go 1.18 下添加了一个间接依赖，但没有运行 `go mod tidy`。然后你尝试用 Go 1.16 构建，可能会遇到类似于以下的错误信息（由 `checkTidyCompatibility` 产生）：

```
example.com/yourmodule/yourpkg loaded from example.com/some/dependency v1.2.3,
	but go1.16 would fail to locate it in example.com/some/dependency v1.2.3
```

这个错误提示你，虽然当前 Go 版本加载了 `example.com/yourmodule/yourpkg`，但在 Go 1.16 下可能无法找到，因为模块依赖图可能不同。这时，你需要运行 `go mod tidy` 来同步 `go.mod` 文件，或者使用 `-compat` 参数来指定兼容的 Go 版本。

Prompt: 
```
这是路径为go/src/cmd/go/internal/modload/load.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共3部分，请归纳一下它的功能

"""

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

"""




```