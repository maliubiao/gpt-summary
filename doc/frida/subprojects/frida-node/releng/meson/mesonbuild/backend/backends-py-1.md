Response:
My thought process for analyzing the Python code and generating the response involved the following steps:

1. **Understanding the Context:**  The initial prompt clearly states that this is part of the Frida dynamic instrumentation tool, specifically a backend module for the Meson build system. This immediately tells me the code's primary purpose is related to generating build instructions and handling build system specifics.

2. **High-Level Code Scan:** I quickly scanned the code to identify major classes, methods, and data structures. Keywords like `rpaths`, `compiler_args`, `link_arguments`, `test_serialisation`, and `install` stood out, providing clues about the functionalities. The use of `@lru_cache` suggests optimization for repeated calculations.

3. **Method-by-Method Analysis:** I then went through the code method by method, focusing on what each function does. For each method, I considered:
    * **Purpose:** What is the main goal of this function?
    * **Inputs:** What arguments does it take? What data does it operate on?
    * **Logic:** What are the key steps within the function?  Are there any conditional branches or loops?
    * **Outputs:** What does the function return?  What side effects might it have?

4. **Identifying Core Functionalities:**  Based on the method analysis, I started grouping related methods to identify core functionalities. This led to categories like:
    * Handling shared libraries and their dependencies (`rpaths_for_non_system_absolute_shared_libraries`, `determine_rpath_dirs`)
    * Generating compiler and linker arguments (`generate_basic_compiler_args`, `build_target_link_arguments`)
    * Managing object file names (`object_filename_from_source`, `canonicalize_filename`)
    * Handling precompiled headers (`get_pch_include_args`, `create_msvc_pch_implementation`)
    * Supporting Windows-specific linking (`get_mingw_extra_paths`, `determine_windows_extra_paths`, `extract_dll_paths`)
    * Generating test definitions (`create_test_serialisation`, `write_test_serialisation`)
    * Handling installation (`generate_depmf_install`)
    * Managing build system regeneration (`get_regen_filelist`, `generate_regen_info`)

5. **Relating to Reverse Engineering:** With a good understanding of the functionalities, I considered how these relate to reverse engineering. Key connections emerged:
    * **RPATH handling:**  Essential for ensuring Frida can load its agent libraries at runtime.
    * **Compiler/linker flags:**  Understanding these can reveal how Frida itself is built and potentially expose security-relevant build options.
    * **Windows DLL paths:**  Critical for Frida's operation on Windows, as it needs to find its dependencies.
    * **Test framework:** While not directly reverse engineering, the test framework hints at Frida's internal architecture and how it's validated.

6. **Identifying Binary/Kernel/Framework Aspects:**  I looked for methods that explicitly dealt with low-level details:
    * **Object file suffixes:**  `.o` for Linux, `.obj` for Windows – a direct connection to binary formats.
    * **Shared library handling:**  `.so`, `.dll`, `.dylib` – binary formats and operating system conventions.
    * **Kernel (implicitly):** While the code doesn't directly interact with the kernel, the handling of shared libraries and RPATHs is fundamental to how operating systems load and execute code. Frida's core functionality relies heavily on these OS mechanisms.
    * **Android (implicitly):** Although not explicitly mentioned in *this snippet*, Frida is widely used on Android, and the concepts of shared libraries and dynamic linking are crucial on that platform. The code's flexibility in handling different platforms suggests it contributes to Frida's Android support.

7. **Logical Reasoning (Input/Output):** I selected a few methods with clear input-output relationships to demonstrate logical reasoning. The `rpaths_for_non_system_absolute_shared_libraries` method was a good candidate, as its purpose is well-defined. I created a simplified example to illustrate the expected output.

8. **Common User/Programming Errors:** I thought about how users might misuse Frida or the build system, focusing on errors related to the functionalities in the code. Incorrect RPATH settings and dependency issues on Windows were relevant examples.

9. **User Journey/Debugging:** I traced back how a user might end up interacting with this specific code. Configuring the build system, especially with shared libraries or cross-compilation, are likely scenarios that would involve these backend components.

10. **Summarization:** Finally, I synthesized my findings into a concise summary, highlighting the key roles of the code in the build process, particularly for handling shared libraries, compiler/linker settings, and platform-specific details. I reiterated its importance for Frida's dynamic instrumentation capabilities.

Throughout this process, I paid attention to the constraints of the prompt (listing functionalities, examples for reverse engineering, binary/kernel/framework aspects, logical reasoning, user errors, debugging, and summarization). I aimed for clear and concise explanations, providing specific examples where possible.
This Python code snippet is a part of the Meson build system backend specifically for generating build files for Frida's Node.js bindings. It focuses on tasks related to compiling, linking, and packaging software, especially handling shared libraries and testing. Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Managing Shared Library Dependencies (RPATHs):**
   - **`rpaths_for_non_system_absolute_shared_libraries`:**  This function determines the runtime search paths (RPATHs) for shared libraries that are not part of the system. It analyzes the dependencies of a build target and identifies the directories containing the required shared libraries. This is crucial for ensuring that when an executable is run, it can find its dependent shared libraries.
   - **`determine_rpath_dirs`:**  This method consolidates the RPATH directories needed for a target, considering both internal dependencies and external shared libraries. It takes into account the build layout ('mirror' or standard).
   - **`get_external_rpath_dirs` and `get_rpath_dirs_from_link_args`:** These helper functions extract existing RPATH information from link arguments, preventing duplication.

2. **Handling Object File Naming:**
   - **`canonicalize_filename`:** This function generates a canonical, platform-independent filename for object files, handling potential path length issues by hashing parts of the path if it's too long.
   - **`object_filename_from_source`:** This method determines the object file name corresponding to a given source file, considering factors like generated sources (e.g., from Vala), precompiled headers, and unity builds.

3. **Generating Compiler and Linker Arguments:**
   - **`generate_basic_compiler_args`:** This function constructs the base set of compiler arguments for a target, taking into account various factors like optimization level, debug settings, include paths, preprocessor definitions, and language-specific options.
   - **`build_target_link_arguments`:** This method generates the linker arguments needed to link against other build targets (libraries). It constructs the correct library names and prefixes for the linker.
   - **`get_no_stdlib_args`:** Determines the arguments to exclude standard library includes if necessary.
   - **`get_pch_include_args`:**  Gets the necessary include arguments for precompiled headers.

4. **Managing Precompiled Headers (PCH):**
   - **`get_msvc_pch_objname`:**  Gets the object file name for a precompiled header on MSVC.
   - **`create_msvc_pch_implementation`:** Creates the source file for a precompiled header on MSVC.
   - **`target_uses_pch`:**  Checks if precompiled headers are enabled for a target.

5. **Windows-Specific Linking:**
   - **`get_mingw_extra_paths`:** On MinGW (Windows), this function determines extra paths where DLLs might be located.
   - **`search_dll_path` and `extract_dll_paths`:** These methods help locate the paths to required DLLs on Windows, as Windows doesn't have RPATHs in the same way as Linux.
   - **`determine_windows_extra_paths`:**  This function identifies all the directories containing DLLs that an executable links against on Windows.

6. **Generating Test Definitions:**
   - **`write_benchmark_file` and `write_test_file`:** These functions serialize the definitions of benchmarks and tests into files.
   - **`create_test_serialisation`:** This method prepares the data structure for test serialization, including the command to run the test, environment variables, dependencies, and other relevant information.
   - **`construct_target_rel_paths`:**  Generates the relative paths to target outputs for use in test commands.

7. **Handling Installation:**
   - **`generate_depmf_install`:**  Generates installation instructions for dependency manifest files, which contain information about the project's dependencies and licenses.

8. **Managing Build System Regeneration:**
   - **`get_regen_filelist`:**  Lists files that, if modified, require the build system to be regenerated (e.g., `meson.build` files, cross-compilation files).
   - **`generate_regen_info`:**  Creates a file containing information about the files that trigger build system regeneration.
   - **`check_clock_skew`:** Detects potential clock skew issues that could lead to infinite build system regeneration loops.

9. **Utility Functions:**
   - **`escape_extra_args`:**  Escapes backslashes in extra compiler arguments.
   - **`replace_extra_args` and `replace_outputs`:** These functions help in processing command-line arguments for custom targets, replacing placeholders with actual values.
   - **`get_build_by_default_targets`:** Retrieves targets that should be built by default.
   - **`get_testlike_targets`:** Retrieves targets that are tests or benchmarks.

**Relationship to Reverse Engineering:**

* **RPATH Management:** Understanding how RPATHs are set is crucial in reverse engineering. RPATHs determine where the dynamic linker searches for shared libraries at runtime. By examining the generated build files or the executable's metadata, a reverse engineer can identify the expected locations of dependencies, which can be helpful in understanding how the application is structured and what libraries it relies on. For instance, if a Frida gadget library is being built and its RPATH is being set, a reverse engineer would know where to expect this library to be loaded from.

* **Compiler and Linker Arguments:** The compiler and linker flags used during the build process can provide valuable insights into the security posture and functionality of the target. Flags related to stack canaries, position-independent code (PIC), and other security features can be identified. For example, the presence of `-fPIC` in the compiler arguments suggests that the code is being built to be loaded at arbitrary memory addresses, which is common for shared libraries and can be a relevant detail in analyzing code execution.

* **Windows DLL Path Handling:** On Windows, the equivalent of RPATHs involves setting the `PATH` environment variable or having DLLs in specific directories. The functions related to Windows DLL paths demonstrate how the build system ensures that executables can find their required DLLs. A reverse engineer analyzing a Frida component on Windows might look at how the build system arranges DLLs to understand the loading process.

**Binary 底层, Linux, Android 内核及框架知识:**

* **Shared Libraries (`.so`, `.dll`, `.dylib`):** The code extensively deals with shared libraries, which are a fundamental concept in operating systems like Linux, macOS, and Windows. It understands the different file extensions and the mechanisms for loading them (dynamic linking).
* **RPATH on Linux:** The RPATH mechanism is a Linux-specific feature (and similar mechanisms exist on macOS). The code demonstrates knowledge of how RPATHs are set using linker flags and how they influence the dynamic linker's behavior.
* **Dynamic Linking:** The entire concept of RPATHs and DLL path handling revolves around dynamic linking, where libraries are loaded at runtime rather than being statically linked into the executable. This is a core operating system concept.
* **Object Files (`.o`, `.obj`):** The code deals with the creation and naming of object files, which are the intermediate compiled output before linking. This is a low-level aspect of the compilation process.
* **Precompiled Headers:**  Precompiled headers are a compiler optimization technique to speed up compilation, and the code includes logic to handle them, demonstrating knowledge of compiler internals.
* **Executable Wrappers (implicitly):**  While not explicitly a kernel feature, the mention of `exe_wrapper` suggests awareness of scenarios where executables might need to be run through a wrapper script or tool, which can be common in cross-compilation or when using emulators/simulators. This is relevant to how Frida might interact with target processes.

**逻辑推理 (假设输入与输出):**

Let's consider the `rpaths_for_non_system_absolute_shared_libraries` function:

**假设输入:**

* `target`: A `build.BuildTarget` object representing an executable.
* This executable has an external dependency (`dep`) that is a shared library located at `/opt/mylibs/libfoo.so`.
* The system library directories do *not* include `/opt/mylibs`.

**预期输出:**

A list containing the string `/opt/mylibs`. This is because the function identifies the absolute path to the external shared library and, since it's not a system library path, adds its directory to the RPATHs.

**Another Example: `object_filename_from_source`**

**假设输入:**

* `target`: A `build.BuildTarget` object.
* `source`: A `mesonlib.File` object representing a source file named `myfile.c` located in the source directory `src`.
* `build_to_src` is set to `..` (meaning the build directory is one level above the source directory).

**预期输出:**

A string like `src_myfile.c.o` (on Linux) or `src_myfile.c.obj` (on Windows). The function constructs the object file name based on the source file path relative to the source root and appends the appropriate object file suffix.

**用户或编程常见的使用错误:**

* **Incorrectly Specified External Dependencies:** If a user provides an incorrect path to an external shared library, the `rpaths_for_non_system_absolute_shared_libraries` function might not be able to locate it, or the generated RPATH might be wrong. This would lead to runtime errors when the executable tries to load the library.

* **Forgetting to Install Shared Libraries:**  Even if RPATHs are correctly set, if the user forgets to copy the required shared libraries to the specified RPATH directories during the installation process, the application will fail to run.

* **Conflicting Library Versions:**  If multiple versions of the same shared library are present in the RPATHs, the dynamic linker might pick the wrong one, leading to unexpected behavior or crashes.

* **Windows DLL Hell:** On Windows, failing to ensure that required DLLs are in the `PATH` or the same directory as the executable is a common issue. The Windows-specific functions in the code try to mitigate this, but users can still encounter problems if dependencies are not properly managed.

**用户操作如何一步步的到达这里 (调试线索):**

1. **User configures the Frida Node.js build using Meson:** The user runs `meson setup builddir` in their terminal. This starts the Meson configuration process.
2. **Meson parses `meson.build` files:** Meson reads the `meson.build` files in the Frida Node.js project, which define the build targets, dependencies, and other build settings.
3. **A shared library target is encountered:**  The `meson.build` files define a target that is a shared library (e.g., a Frida gadget).
4. **Meson needs to determine the RPATHs for this library:**  When processing this shared library target, Meson's backend (including this `backends.py` file) needs to figure out the correct RPATHs so that executables linking against this library can find it at runtime.
5. **`rpaths_for_non_system_absolute_shared_libraries` is called:**  The Meson backend calls this function to calculate the necessary RPATHs based on the library's dependencies.
6. **The function analyzes dependencies:** The function iterates through the library's dependencies, looking for absolute paths to shared library files.
7. **RPATHs are added:**  Based on the location of these dependencies, the function determines the directories that need to be added to the RPATH.
8. **Build files are generated:** Meson generates the final build files (e.g., Makefiles or Ninja files) that contain the instructions for compiling and linking the software, including the RPATH settings.

During debugging, if a user encounters issues with shared libraries not being found at runtime, they might investigate the generated build files or the output of the linking command to see how the RPATHs were set. They might then trace back to this `backends.py` file to understand how Meson determined those RPATHs.

**归纳功能 (第2部分):**

This part of the `backends.py` file primarily focuses on the **generation of compiler and linker commands, particularly concerning shared library dependencies (RPATHs) and Windows-specific DLL handling.** It also handles object file naming conventions and lays the groundwork for the test framework by providing functions for test serialization and path construction. Essentially, it's responsible for the crucial steps of translating the high-level build definitions into the concrete instructions needed to compile and link the Frida Node.js components, ensuring that shared libraries can be found at runtime.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
if Path(dir).is_dir():
                        dirs.add(dir)
            symbols_match = symbols_regex.match(arg)
            if symbols_match:
                for dir in symbols_match.group(1).split(':'):
                    # Prevent usage of --just-symbols to specify rpath
                    if Path(dir).is_dir():
                        raise MesonException(f'Invalid arg for --just-symbols, {dir} is a directory.')
        return dirs

    @lru_cache(maxsize=None)
    def rpaths_for_non_system_absolute_shared_libraries(self, target: build.BuildTarget, exclude_system: bool = True) -> 'ImmutableListProtocol[str]':
        paths: OrderedSet[str] = OrderedSet()
        srcdir = self.environment.get_source_dir()

        for dep in target.external_deps:
            if dep.type_name not in {'library', 'pkgconfig', 'cmake'}:
                continue
            for libpath in dep.link_args:
                # For all link args that are absolute paths to a library file, add RPATH args
                if not os.path.isabs(libpath):
                    continue
                libdir = os.path.dirname(libpath)
                if exclude_system and self._libdir_is_system(libdir, target.compilers, self.environment):
                    # No point in adding system paths.
                    continue
                # Don't remove rpaths specified in LDFLAGS.
                if libdir in self.get_external_rpath_dirs(target):
                    continue
                # Windows doesn't support rpaths, but we use this function to
                # emulate rpaths by setting PATH
                # .dll is there for mingw gcc
                # .so's may be extended with version information, e.g. libxyz.so.1.2.3
                if not (
                    os.path.splitext(libpath)[1] in {'.dll', '.lib', '.so', '.dylib'}
                    or re.match(r'.+\.so(\.|$)', os.path.basename(libpath))
                ):
                    continue

                try:
                    commonpath = os.path.commonpath((libdir, srcdir))
                except ValueError: # when paths are on different drives on Windows
                    commonpath = ''

                if commonpath == srcdir:
                    rel_to_src = libdir[len(srcdir) + 1:]
                    assert not os.path.isabs(rel_to_src), f'rel_to_src: {rel_to_src} is absolute'
                    paths.add(os.path.join(self.build_to_src, rel_to_src))
                else:
                    paths.add(libdir)
            # Don't remove rpaths specified by the dependency
            paths.difference_update(self.get_rpath_dirs_from_link_args(dep.link_args))
        for i in chain(target.link_targets, target.link_whole_targets):
            if isinstance(i, build.BuildTarget):
                paths.update(self.rpaths_for_non_system_absolute_shared_libraries(i, exclude_system))
        return list(paths)

    # This may take other types
    def determine_rpath_dirs(self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]
                             ) -> T.Tuple[str, ...]:
        result: OrderedSet[str]
        if self.environment.coredata.get_option(OptionKey('layout')) == 'mirror':
            # Need a copy here
            result = OrderedSet(target.get_link_dep_subdirs())
        else:
            result = OrderedSet()
            result.add('meson-out')
        if isinstance(target, build.BuildTarget):
            result.update(self.rpaths_for_non_system_absolute_shared_libraries(target))
            target.rpath_dirs_to_remove.update([d.encode('utf-8') for d in result])
        return tuple(result)

    @staticmethod
    def canonicalize_filename(fname: str) -> str:
        parts = Path(fname).parts
        hashed = ''
        if len(parts) > 5:
            temp = '/'.join(parts[-5:])
            # is it shorter to hash the beginning of the path?
            if len(fname) > len(temp) + 41:
                hashed = hashlib.sha1(fname.encode('utf-8')).hexdigest() + '_'
                fname = temp
        for ch in ('/', '\\', ':'):
            fname = fname.replace(ch, '_')
        return hashed + fname

    def object_filename_from_source(self, target: build.BuildTarget, source: 'FileOrString', targetdir: T.Optional[str] = None) -> str:
        assert isinstance(source, mesonlib.File)
        if isinstance(target, build.CompileTarget):
            return target.sources_map[source]
        build_dir = self.environment.get_build_dir()
        rel_src = source.rel_to_builddir(self.build_to_src)

        # foo.vala files compile down to foo.c and then foo.c.o, not foo.vala.o
        if rel_src.endswith(('.vala', '.gs')):
            # See description in generate_vala_compile for this logic.
            if source.is_built:
                if os.path.isabs(rel_src):
                    rel_src = rel_src[len(build_dir) + 1:]
                rel_src = os.path.relpath(rel_src, self.get_target_private_dir(target))
            else:
                rel_src = os.path.basename(rel_src)
            # A meson- prefixed directory is reserved; hopefully no-one creates a file name with such a weird prefix.
            gen_source = 'meson-generated_' + rel_src[:-5] + '.c'
        elif source.is_built:
            if os.path.isabs(rel_src):
                rel_src = rel_src[len(build_dir) + 1:]
            # A meson- prefixed directory is reserved; hopefully no-one creates a file name with such a weird prefix.
            gen_source = 'meson-generated_' + os.path.relpath(rel_src, self.get_target_private_dir(target))
        else:
            if os.path.isabs(rel_src):
                # Use the absolute path directly to avoid file name conflicts
                gen_source = rel_src
            else:
                gen_source = os.path.relpath(os.path.join(build_dir, rel_src),
                                             os.path.join(self.environment.get_source_dir(), target.get_source_subdir()))
        machine = self.environment.machines[target.for_machine]
        ret = self.canonicalize_filename(gen_source) + '.' + machine.get_object_suffix()
        if targetdir is not None:
            return os.path.join(targetdir, ret)
        return ret

    def _determine_ext_objs(self, extobj: 'build.ExtractedObjects', proj_dir_to_build_root: str) -> T.List[str]:
        result: T.List[str] = []

        targetdir = self.get_target_private_dir(extobj.target)

        # Merge sources and generated sources
        raw_sources = list(extobj.srclist)
        for gensrc in extobj.genlist:
            for r in gensrc.get_outputs():
                path = self.get_target_generated_dir(extobj.target, gensrc, r)
                dirpart, fnamepart = os.path.split(path)
                raw_sources.append(File(True, dirpart, fnamepart))

        # Filter out headers and all non-source files
        sources: T.List['FileOrString'] = []
        for s in raw_sources:
            if self.environment.is_source(s):
                sources.append(s)
            elif self.environment.is_object(s):
                result.append(s.relative_name())

        # MSVC generate an object file for PCH
        if extobj.pch and self.target_uses_pch(extobj.target):
            for lang, pch in extobj.target.pch.items():
                compiler = extobj.target.compilers[lang]
                if compiler.get_argument_syntax() == 'msvc':
                    objname = self.get_msvc_pch_objname(lang, pch)
                    result.append(os.path.join(proj_dir_to_build_root, targetdir, objname))

        # extobj could contain only objects and no sources
        if not sources:
            return result

        # With unity builds, sources don't map directly to objects,
        # we only support extracting all the objects in this mode,
        # so just return all object files.
        if extobj.target.is_unity:
            compsrcs = classify_unity_sources(extobj.target.compilers.values(), sources)
            sources = []
            unity_size = extobj.target.get_option(OptionKey('unity_size'))
            assert isinstance(unity_size, int), 'for mypy'

            for comp, srcs in compsrcs.items():
                if comp.language in LANGS_CANT_UNITY:
                    sources += srcs
                    continue
                for i in range((len(srcs) + unity_size - 1) // unity_size):
                    _src = self.get_unity_source_file(extobj.target,
                                                      comp.get_default_suffix(), i)
                    sources.append(_src)

        for osrc in sources:
            objname = self.object_filename_from_source(extobj.target, osrc, targetdir)
            objpath = os.path.join(proj_dir_to_build_root, objname)
            result.append(objpath)

        return result

    def get_pch_include_args(self, compiler: 'Compiler', target: build.BuildTarget) -> T.List[str]:
        args: T.List[str] = []
        pchpath = self.get_target_private_dir(target)
        includeargs = compiler.get_include_args(pchpath, False)
        p = target.get_pch(compiler.get_language())
        if p:
            args += compiler.get_pch_use_args(pchpath, p[0])
        return includeargs + args

    def get_msvc_pch_objname(self, lang: str, pch: T.List[str]) -> str:
        if len(pch) == 1:
            # Same name as in create_msvc_pch_implementation() below.
            return f'meson_pch-{lang}.obj'
        return os.path.splitext(pch[1])[0] + '.obj'

    def create_msvc_pch_implementation(self, target: build.BuildTarget, lang: str, pch_header: str) -> str:
        # We have to include the language in the file name, otherwise
        # pch.c and pch.cpp will both end up as pch.obj in VS backends.
        impl_name = f'meson_pch-{lang}.{lang}'
        pch_rel_to_build = os.path.join(self.get_target_private_dir(target), impl_name)
        # Make sure to prepend the build dir, since the working directory is
        # not defined. Otherwise, we might create the file in the wrong path.
        pch_file = os.path.join(self.build_dir, pch_rel_to_build)
        os.makedirs(os.path.dirname(pch_file), exist_ok=True)

        content = f'#include "{os.path.basename(pch_header)}"'
        pch_file_tmp = pch_file + '.tmp'
        with open(pch_file_tmp, 'w', encoding='utf-8') as f:
            f.write(content)
        mesonlib.replace_if_different(pch_file, pch_file_tmp)
        return pch_rel_to_build

    def target_uses_pch(self, target: build.BuildTarget) -> bool:
        try:
            return T.cast('bool', target.get_option(OptionKey('b_pch')))
        except KeyError:
            return False

    @staticmethod
    def escape_extra_args(args: T.List[str]) -> T.List[str]:
        # all backslashes in defines are doubly-escaped
        extra_args: T.List[str] = []
        for arg in args:
            if arg.startswith(('-D', '/D')):
                arg = arg.replace('\\', '\\\\')
            extra_args.append(arg)

        return extra_args

    def get_no_stdlib_args(self, target: 'build.BuildTarget', compiler: 'Compiler') -> T.List[str]:
        if compiler.language in self.build.stdlibs[target.for_machine]:
            return compiler.get_no_stdinc_args()
        return []

    def generate_basic_compiler_args(self, target: build.BuildTarget, compiler: 'Compiler') -> 'CompilerArgs':
        # Create an empty commands list, and start adding arguments from
        # various sources in the order in which they must override each other
        # starting from hard-coded defaults followed by build options and so on.
        commands = compiler.compiler_args()

        copt_proxy = target.get_options()
        # First, the trivial ones that are impossible to override.
        #
        # Add -nostdinc/-nostdinc++ if needed; can't be overridden
        commands += self.get_no_stdlib_args(target, compiler)
        # Add things like /NOLOGO or -pipe; usually can't be overridden
        commands += compiler.get_always_args()
        # warning_level is a string, but mypy can't determine that
        commands += compiler.get_warn_args(T.cast('str', target.get_option(OptionKey('warning_level'))))
        # Add -Werror if werror=true is set in the build options set on the
        # command-line or default_options inside project(). This only sets the
        # action to be done for warnings if/when they are emitted, so it's ok
        # to set it after or get_warn_args().
        if target.get_option(OptionKey('werror')):
            commands += compiler.get_werror_args()
        # Add compile args for c_* or cpp_* build options set on the
        # command-line or default_options inside project().
        commands += compiler.get_option_compile_args(copt_proxy)

        optimization = target.get_option(OptionKey('optimization'))
        assert isinstance(optimization, str), 'for mypy'
        commands += compiler.get_optimization_args(optimization)

        debug = target.get_option(OptionKey('debug'))
        assert isinstance(debug, bool), 'for mypy'
        commands += compiler.get_debug_args(debug)

        # Add compile args added using add_project_arguments()
        commands += self.build.get_project_args(compiler, target.subproject, target.for_machine)
        # Add compile args added using add_global_arguments()
        # These override per-project arguments
        commands += self.build.get_global_args(compiler, target.for_machine)
        # Compile args added from the env: CFLAGS/CXXFLAGS, etc, or the cross
        # file. We want these to override all the defaults, but not the
        # per-target compile args.
        commands += self.environment.coredata.get_external_args(target.for_machine, compiler.get_language())
        # Using both /Z7 or /ZI and /Zi at the same times produces a compiler warning.
        # We do not add /Z7 or /ZI by default. If it is being used it is because the user has explicitly enabled it.
        # /Zi needs to be removed in that case to avoid cl's warning to that effect (D9025 : overriding '/Zi' with '/ZI')
        if ('/Zi' in commands) and (('/ZI' in commands) or ('/Z7' in commands)):
            commands.remove('/Zi')
        # Always set -fPIC for shared libraries
        if isinstance(target, build.SharedLibrary):
            commands += compiler.get_pic_args()
        # Set -fPIC for static libraries by default unless explicitly disabled
        if isinstance(target, build.StaticLibrary) and target.pic:
            commands += compiler.get_pic_args()
        elif isinstance(target, (build.StaticLibrary, build.Executable)) and target.pie:
            commands += compiler.get_pie_args()
        # Add compile args needed to find external dependencies. Link args are
        # added while generating the link command.
        # NOTE: We must preserve the order in which external deps are
        # specified, so we reverse the list before iterating over it.
        for dep in reversed(target.get_external_deps()):
            if not dep.found():
                continue

            if compiler.language == 'vala':
                if dep.type_name == 'pkgconfig':
                    assert isinstance(dep, dependencies.ExternalDependency)
                    if dep.name == 'glib-2.0' and dep.version_reqs is not None:
                        for req in dep.version_reqs:
                            if req.startswith(('>=', '==')):
                                commands += ['--target-glib', req[2:].lstrip()]
                                break
                    commands += ['--pkg', dep.name]
                elif isinstance(dep, dependencies.ExternalLibrary):
                    commands += dep.get_link_args('vala')
            else:
                commands += compiler.get_dependency_compile_args(dep)
            # Qt needs -fPIC for executables
            # XXX: We should move to -fPIC for all executables
            if isinstance(target, build.Executable):
                commands += dep.get_exe_args(compiler)
            # For 'automagic' deps: Boost and GTest. Also dependency('threads').
            # pkg-config puts the thread flags itself via `Cflags:`
        # Fortran requires extra include directives.
        if compiler.language == 'fortran':
            for lt in chain(target.link_targets, target.link_whole_targets):
                priv_dir = self.get_target_private_dir(lt)
                commands += compiler.get_include_args(priv_dir, False)
        return commands

    def build_target_link_arguments(self, compiler: 'Compiler', deps: T.List[build.Target]) -> T.List[str]:
        args: T.List[str] = []
        for d in deps:
            if not d.is_linkable_target():
                raise RuntimeError(f'Tried to link with a non-library target "{d.get_basename()}".')
            arg = self.get_target_filename_for_linking(d)
            if not arg:
                continue
            if compiler.get_language() == 'd':
                arg = '-Wl,' + arg
            else:
                arg = compiler.get_linker_lib_prefix() + arg
            args.append(arg)
        return args

    def get_mingw_extra_paths(self, target: build.BuildTarget) -> T.List[str]:
        paths: OrderedSet[str] = OrderedSet()
        # The cross bindir
        root = self.environment.properties[target.for_machine].get_root()
        if root:
            paths.add(os.path.join(root, 'bin'))
        # The toolchain bindir
        sys_root = self.environment.properties[target.for_machine].get_sys_root()
        if sys_root:
            paths.add(os.path.join(sys_root, 'bin'))
        # Get program and library dirs from all target compilers
        if isinstance(target, build.BuildTarget):
            for cc in target.compilers.values():
                paths.update(cc.get_program_dirs(self.environment))
                paths.update(cc.get_library_dirs(self.environment))
        return list(paths)

    @staticmethod
    @lru_cache(maxsize=None)
    def search_dll_path(link_arg: str) -> T.Optional[str]:
        if link_arg.startswith(('-l', '-L')):
            link_arg = link_arg[2:]

        p = Path(link_arg)
        if not p.is_absolute():
            return None

        try:
            p = p.resolve(strict=True)
        except FileNotFoundError:
            return None

        for f in p.parent.glob('*.dll'):
            # path contains dlls
            return str(p.parent)

        if p.is_file():
            p = p.parent
        # Heuristic: replace *last* occurence of '/lib'
        binpath = Path('/bin'.join(p.as_posix().rsplit('/lib', maxsplit=1)))
        for _ in binpath.glob('*.dll'):
            return str(binpath)

        return None

    @classmethod
    @lru_cache(maxsize=None)
    def extract_dll_paths(cls, target: build.BuildTarget) -> T.Set[str]:
        """Find paths to all DLLs needed for a given target, since
        we link against import libs, and we don't know the actual
        path of the DLLs.

        1. If there are DLLs in the same directory than the .lib dir, use it
        2. If there is a sibbling directory named 'bin' with DLLs in it, use it
        """
        results = set()
        for dep in target.external_deps:

            if dep.type_name == 'pkgconfig':
                # If by chance pkg-config knows the bin dir...
                bindir = dep.get_variable(pkgconfig='bindir', default_value='')
                if bindir:
                    results.add(bindir)
                    continue

            results.update(filter(None, map(cls.search_dll_path, dep.link_args)))  # pylint: disable=bad-builtin

        for i in chain(target.link_targets, target.link_whole_targets):
            if isinstance(i, build.BuildTarget):
                results.update(cls.extract_dll_paths(i))

        return results

    def determine_windows_extra_paths(
            self, target: T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, programs.ExternalProgram, mesonlib.File, str],
            extra_bdeps: T.Sequence[T.Union[build.BuildTarget, build.CustomTarget]]) -> T.List[str]:
        """On Windows there is no such thing as an rpath.

        We must determine all locations of DLLs that this exe
        links to and return them so they can be used in unit
        tests.
        """
        result: T.Set[str] = set()
        prospectives: T.Set[build.BuildTargetTypes] = set()
        if isinstance(target, build.BuildTarget):
            prospectives.update(target.get_transitive_link_deps())
            # External deps
            result.update(self.extract_dll_paths(target))

        for bdep in extra_bdeps:
            prospectives.add(bdep)
            if isinstance(bdep, build.BuildTarget):
                prospectives.update(bdep.get_transitive_link_deps())
        # Internal deps
        for ld in prospectives:
            dirseg = os.path.join(self.environment.get_build_dir(), self.get_target_dir(ld))
            result.add(dirseg)
        if (isinstance(target, build.BuildTarget) and
                not self.environment.machines.matches_build_machine(target.for_machine)):
            result.update(self.get_mingw_extra_paths(target))
        return list(result)

    def write_benchmark_file(self, datafile: T.BinaryIO) -> None:
        self.write_test_serialisation(self.build.get_benchmarks(), datafile)

    def write_test_file(self, datafile: T.BinaryIO) -> None:
        self.write_test_serialisation(self.build.get_tests(), datafile)

    def create_test_serialisation(self, tests: T.List['Test']) -> T.List[TestSerialisation]:
        arr: T.List[TestSerialisation] = []
        for t in sorted(tests, key=lambda tst: -1 * tst.priority):
            exe = t.get_exe()
            if isinstance(exe, programs.ExternalProgram):
                cmd = exe.get_command()
            else:
                cmd = [os.path.join(self.environment.get_build_dir(), self.get_target_filename(exe))]
            if isinstance(exe, (build.BuildTarget, programs.ExternalProgram)):
                test_for_machine = exe.for_machine
            else:
                # E.g. an external verifier or simulator program run on a generated executable.
                # Can always be run without a wrapper.
                test_for_machine = MachineChoice.BUILD

            # we allow passing compiled executables to tests, which may be cross built.
            # We need to consider these as well when considering whether the target is cross or not.
            for a in t.cmd_args:
                if isinstance(a, build.BuildTarget):
                    if a.for_machine is MachineChoice.HOST:
                        test_for_machine = MachineChoice.HOST
                        break

            is_cross = self.environment.is_cross_build(test_for_machine)
            exe_wrapper = self.environment.get_exe_wrapper()
            machine = self.environment.machines[exe.for_machine]
            if machine.is_windows() or machine.is_cygwin():
                extra_bdeps: T.List[T.Union[build.BuildTarget, build.CustomTarget]] = []
                if isinstance(exe, build.CustomTarget):
                    extra_bdeps = list(exe.get_transitive_build_target_deps())
                extra_paths = self.determine_windows_extra_paths(exe, extra_bdeps)
                for a in t.cmd_args:
                    if isinstance(a, build.BuildTarget):
                        for p in self.determine_windows_extra_paths(a, []):
                            if p not in extra_paths:
                                extra_paths.append(p)
            else:
                extra_paths = []

            cmd_args: T.List[str] = []
            depends: T.Set[build.Target] = set(t.depends)
            if isinstance(exe, build.Target):
                depends.add(exe)
            for a in t.cmd_args:
                if isinstance(a, build.Target):
                    depends.add(a)
                elif isinstance(a, build.CustomTargetIndex):
                    depends.add(a.target)

                if isinstance(a, mesonlib.File):
                    a = os.path.join(self.environment.get_build_dir(), a.rel_to_builddir(self.build_to_src))
                    cmd_args.append(a)
                elif isinstance(a, str):
                    cmd_args.append(a)
                elif isinstance(a, (build.Target, build.CustomTargetIndex)):
                    cmd_args.extend(self.construct_target_rel_paths(a, t.workdir))
                else:
                    raise MesonException('Bad object in test command.')

            t_env = copy.deepcopy(t.env)
            if not machine.is_windows() and not machine.is_cygwin() and not machine.is_darwin():
                ld_lib_path: T.Set[str] = set()
                for d in depends:
                    if isinstance(d, build.BuildTarget):
                        for l in d.get_all_link_deps():
                            if isinstance(l, build.SharedLibrary):
                                ld_lib_path.add(os.path.join(self.environment.get_build_dir(), l.get_output_subdir()))
                if ld_lib_path:
                    t_env.prepend('LD_LIBRARY_PATH', list(ld_lib_path), ':')

            ts = TestSerialisation(t.get_name(), t.project_name, t.suite, cmd, is_cross,
                                   exe_wrapper, self.environment.need_exe_wrapper(),
                                   t.is_parallel, cmd_args, t_env,
                                   t.should_fail, t.timeout, t.workdir,
                                   extra_paths, t.protocol, t.priority,
                                   isinstance(exe, (build.Target, build.CustomTargetIndex)),
                                   isinstance(exe, build.Executable),
                                   [x.get_id() for x in depends],
                                   self.environment.coredata.version,
                                   t.verbose)
            arr.append(ts)
        return arr

    def write_test_serialisation(self, tests: T.List['Test'], datafile: T.BinaryIO) -> None:
        pickle.dump(self.create_test_serialisation(tests), datafile)

    def construct_target_rel_paths(self, t: T.Union[build.Target, build.CustomTargetIndex], workdir: T.Optional[str]) -> T.List[str]:
        target_dir = self.get_target_dir(t)
        # ensure that test executables can be run when passed as arguments
        if isinstance(t, build.Executable) and workdir is None:
            target_dir = target_dir or '.'

        if isinstance(t, build.BuildTarget):
            outputs = [t.get_filename()]
        else:
            assert isinstance(t, (build.CustomTarget, build.CustomTargetIndex))
            outputs = t.get_outputs()

        outputs = [os.path.join(target_dir, x) for x in outputs]
        if workdir is not None:
            assert os.path.isabs(workdir)
            outputs = [os.path.join(self.environment.get_build_dir(), x) for x in outputs]
            outputs = [os.path.relpath(x, workdir) for x in outputs]
        return outputs

    def generate_depmf_install(self, d: InstallData) -> None:
        depmf_path = self.build.dep_manifest_name
        if depmf_path is None:
            option_dir = self.environment.coredata.get_option(OptionKey('licensedir'))
            assert isinstance(option_dir, str), 'for mypy'
            if option_dir:
                depmf_path = os.path.join(option_dir, 'depmf.json')
            else:
                return
        ifilename = os.path.join(self.environment.get_build_dir(), 'depmf.json')
        ofilename = os.path.join(self.environment.get_prefix(), depmf_path)
        odirname = os.path.join(self.environment.get_prefix(), os.path.dirname(depmf_path))
        out_name = os.path.join('{prefix}', depmf_path)
        out_dir = os.path.join('{prefix}', os.path.dirname(depmf_path))
        mfobj = {'type': 'dependency manifest', 'version': '1.0',
                 'projects': {k: v.to_json() for k, v in self.build.dep_manifest.items()}}
        with open(ifilename, 'w', encoding='utf-8') as f:
            f.write(json.dumps(mfobj))
        # Copy file from, to, and with mode unchanged
        d.data.append(InstallDataBase(ifilename, ofilename, out_name, None, '',
                                      tag='devel', data_type='depmf'))
        for m in self.build.dep_manifest.values():
            for ifilename, name in m.license_files:
                ofilename = os.path.join(odirname, name.relative_name())
                out_name = os.path.join(out_dir, name.relative_name())
                d.data.append(InstallDataBase(ifilename, ofilename, out_name, None,
                                              m.subproject, tag='devel', data_type='depmf'))

    def get_regen_filelist(self) -> T.List[str]:
        '''List of all files whose alteration means that the build
        definition needs to be regenerated.'''
        deps = OrderedSet([str(Path(self.build_to_src) / df)
                           for df in self.interpreter.get_build_def_files()])
        if self.environment.is_cross_build():
            deps.update(self.environment.coredata.cross_files)
        deps.update(self.environment.coredata.config_files)
        deps.add('meson-private/coredata.dat')
        self.check_clock_skew(deps)
        return list(deps)

    def generate_regen_info(self) -> None:
        deps = self.get_regen_filelist()
        regeninfo = RegenInfo(self.environment.get_source_dir(),
                              self.environment.get_build_dir(),
                              deps)
        filename = os.path.join(self.environment.get_scratch_dir(),
                                'regeninfo.dump')
        with open(filename, 'wb') as f:
            pickle.dump(regeninfo, f)

    def check_clock_skew(self, file_list: T.Iterable[str]) -> None:
        # If a file that leads to reconfiguration has a time
        # stamp in the future, it will trigger an eternal reconfigure
        # loop.
        import time
        now = time.time()
        for f in file_list:
            absf = os.path.join(self.environment.get_build_dir(), f)
            ftime = os.path.getmtime(absf)
            delta = ftime - now
            # On Windows disk time stamps sometimes point
            # to the future by a minuscule amount, less than
            # 0.001 seconds. I don't know why.
            if delta > 0.001:
                raise MesonException(f'Clock skew detected. File {absf} has a time stamp {delta:.4f}s in the future.')

    def build_target_to_cmd_array(self, bt: T.Union[build.BuildTarget, programs.ExternalProgram]) -> T.List[str]:
        if isinstance(bt, build.BuildTarget):
            arr = [os.path.join(self.environment.get_build_dir(), self.get_target_filename(bt))]
        else:
            arr = bt.get_command()
        return arr

    def replace_extra_args(self, args: T.List[str], genlist: 'build.GeneratedList') -> T.List[str]:
        final_args: T.List[str] = []
        for a in args:
            if a == '@EXTRA_ARGS@':
                final_args += genlist.get_extra_args()
            else:
                final_args.append(a)
        return final_args

    def replace_outputs(self, args: T.List[str], private_dir: str, output_list: T.List[str]) -> T.List[str]:
        newargs: T.List[str] = []
        regex = re.compile(r'@OUTPUT(\d+)@')
        for arg in args:
            m = regex.search(arg)
            while m is not None:
                index = int(m.group(1))
                src = f'@OUTPUT{index}@'
                arg = arg.replace(src, os.path.join(private_dir, output_list[index]))
                m = regex.search(arg)
            newargs.append(arg)
        return newargs

    def get_build_by_default_targets(self) -> 'T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]':
        result: 'T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]' = OrderedDict()
        # Get all build and custom targets that must be built by default
        for name, b in self.build.get_targets().items():
            if b.build_by_default:
                result[name] = b
        return result

    def get_testlike_targets(self, benchmark: bool = False) -> T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]]:
        result: T.OrderedDict[str, T.Union[build.BuildTarget, build.CustomTarget]] = OrderedDict()
        targets = self.build.get_benchmarks() if benchmark else self.build.get_tests()
        for t in targets:
            exe = t.exe
            if isinstance(exe, (build.CustomTarget, build.BuildTarget)):
                result[exe.get_id()] = exe
            for arg in t.cmd_args:
                if not isinstance(arg, (build.CustomTarget, build.BuildTarget)):
                    continue
                result[arg.get_id()]
```