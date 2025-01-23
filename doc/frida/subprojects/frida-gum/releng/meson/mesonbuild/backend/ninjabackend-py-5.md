Response:
The user is asking for a summary of the functionality of the provided Python code, which is a part of the Frida dynamic instrumentation tool. This specific file, `ninjabackend.py`, seems to be responsible for generating `build.ninja` files, which are used by the Ninja build system.

I need to analyze the code and identify its main functions. Key areas to focus on include:
- How it handles different types of build targets (libraries, executables, etc.).
- How it manages dependencies between targets.
- How it interacts with the compiler and linker.
- Whether it performs any logic related to reverse engineering or low-level system details.
- Potential user errors in using Frida or Meson that could lead to this code being executed.

Here's a breakdown of the code's functionality:

1. **Prelinking (`generate_prelink`)**: This function seems to generate commands for prelinking, an optimization technique.
2. **Linking (`generate_link`)**: This is a core function that constructs the linker command by accumulating various arguments from different sources (compiler defaults, build options, project settings, environment variables, dependencies). It also handles RPATH settings for finding shared libraries at runtime.
3. **Shared Library Aliases (`generate_shlib_aliases`)**: Creates symbolic links for shared library versions.
4. **Custom Target Cleaning (`generate_custom_target_clean`)**: Generates commands to clean up outputs from custom build targets.
5. **Gcov Cleaning (`generate_gcov_clean`)**: Generates commands to clean up code coverage files.
6. **User Option Handling (`get_user_option_args`)**: Collects user-defined build options.
7. **Distribution Package Generation (`generate_dist`)**: Generates commands for creating source packages.
8. **Static Analysis Tool Integration (`generate_scanbuild`, `generate_clangtool`, `generate_clangformat`, `generate_clangtidy`)**: Integrates with static analysis tools like Clang's scan-build, format, and tidy.
9. **Tag Generation (`generate_tags`)**: Generates tags files for code navigation tools.
10. **Utility Target Generation (`generate_utils`)**: Groups various utility targets like uninstall.
11. **Final Build Targets (`generate_ending`)**: Creates the final `all`, `clean`, `reconfigure`, and other essential build targets.
12. **Introspection Data (`get_introspection_data`)**: Retrieves introspection data about build targets.
13. **Fortran Dependency Scanning (`_scan_fortran_file_deps`)**:  Scans Fortran source files for dependencies based on `include`, `use`, and `submodule` statements.

Now, let's connect these functionalities to the user's specific questions.
This Python code, located in `frida/subprojects/frida-gum/releng/meson/mesonbuild/backend/ninjabackend.py`, is a module within the Meson build system responsible for generating the `build.ninja` file. Ninja is a small build system focused on speed, and Meson uses it as one of its backend options. This specific module defines how Meson translates its build description into Ninja's format.

Here's a breakdown of its functionalities:

**Core Functionality: Generating Ninja Build Rules**

The primary function of this module is to take Meson's internal representation of the project's build structure and translate it into a `build.ninja` file. This file contains the rules and commands that Ninja will execute to build the project.

**Specific Functions and Their Relevance:**

1. **`generate_prelink(self, target, obj_list, prelinker)`:**
    *   **Function:** Generates Ninja rules for prelinking object files. Prelinking is an optimization technique where some linking steps are performed before the final linking stage, potentially speeding up the final link.
    *   **Relevance to Reverse Engineering:** While not directly a reverse engineering method, prelinking can affect the binary layout and might be a factor to consider when analyzing the final executable or library. A reverser might encounter prelinked binaries and need to understand its impact.
    *   **Binary/Low-Level:**  This directly deals with the linking process, a fundamental step in creating binary executables and libraries.
    *   **Logic/Assumptions:** Assumes the presence of a `prelinker` object with a `get_prelink_args` method. The input is a `target` object and a list of object files (`obj_list`). The output is the name of the prelinked file.
        *   **Input Example:** `target` representing a shared library, `obj_list` containing the `.o` files for that library.
        *   **Output Example:** The filename of the prelinked output (e.g., `libmylibrary.prelink`).

2. **`generate_link(self, target, outname, obj_list, linker, extra_args=None, stdlib_args=None)`:**
    *   **Function:**  This is a crucial function that generates the Ninja rule for linking. It orchestrates the linker command by collecting arguments from various sources (compiler defaults, build options, project settings, environment variables, dependencies). It handles linking static and shared libraries, executables, and shared modules.
    *   **Relevance to Reverse Engineering:** This is highly relevant. The linker command determines the final structure of the binary, including symbol resolution, library dependencies, and runtime paths. Understanding linker flags is essential for reverse engineering to analyze dependencies, relocation information, and potential security implications.
        *   **Example:**  The `-Wl,-soname` flag (or equivalent on other platforms) for shared libraries sets the "real" name of the library at runtime. A reverser will see this name embedded in the binary.
        *   **Example:**  Linker flags controlling Position Independent Code (PIC) or Address Space Layout Randomization (ASLR) are important security considerations when reverse engineering.
    *   **Binary/Low-Level:** Directly interacts with the linker, which operates on binary object files to produce final binaries.
    *   **Linux/Android Kernel/Framework:** The code handles RPATH (`build_rpath_args`), which is crucial for finding shared libraries at runtime on Linux and Android. This is especially relevant for framework components.
    *   **Logic/Assumptions:**  It assumes different linkers (compiler-based or dedicated static linkers) have different methods for generating link arguments. It handles various target types (`StaticLibrary`, `SharedLibrary`, `SharedModule`).
        *   **Input Example:** `target` representing an executable, `outname` being the executable's name, `obj_list` being the object files, `linker` being the C++ compiler object.
        *   **Output Example:** A `NinjaBuildElement` representing the link rule in `build.ninja`.
    *   **User/Programming Errors:** Incorrectly specifying link dependencies in `meson.build` might lead to missing symbols during linking, causing build failures handled by this code.

3. **`generate_shsym(self, target)`:**
    *   **Function:** Generates a symbol file (e.g., `.shsym`) for shared libraries. This file can be used for faster incremental linking.
    *   **Relevance to Reverse Engineering:** While not directly exposed in the final binary, these symbol files can contain debugging information or symbol tables that could be indirectly useful during development or debugging.
    *   **Binary/Low-Level:** Deals with symbol information, a low-level aspect of binary files.

4. **`generate_shlib_aliases(self, target, outdir)`:**
    *   **Function:** Creates symbolic links for different versions of shared libraries. This is common on Linux to maintain backward compatibility.
    *   **Relevance to Reverse Engineering:** When reverse engineering on Linux, it's essential to understand the versioning schemes of shared libraries and how symbolic links point to the actual library being used.
    *   **Linux:** Specifically relevant to how shared libraries are managed in Linux environments.
    *   **User/Programming Errors:** Incorrect versioning information in the Meson configuration can lead to broken symbolic links.

5. **`generate_custom_target_clean(self, trees)`:**
    *   **Function:** Generates commands to clean the output directories of custom build targets.
    *   **User Interaction:** This is triggered when the user runs `ninja clean`.

6. **`generate_gcov_clean(self)`:**
    *   **Function:** Generates commands to clean up code coverage files (`.gcno`, `.gcda`) generated by tools like `gcov`.
    *   **User Interaction:** Triggered when the user runs `ninja clean` and code coverage is enabled.

7. **`get_user_option_args(self)`:**
    *   **Function:** Collects the user-specified options passed to Meson (e.g., `-Dmyoption=value`). These options can influence the build process.
    *   **User Interaction:** This reflects the options the user provided during the initial Meson configuration step.

8. **`generate_dist(self)`:**
    *   **Function:** Generates a Ninja rule for creating distribution packages (e.g., source tarballs).
    *   **User Interaction:** Triggered when the user runs `ninja dist`.

9. **`generate_scanbuild(self)`, `generate_clangtool(self, name, extra_arg=None)`, `generate_clangformat(self)`, `generate_clangtidy(self)`:**
    *   **Function:** Integrates with static analysis tools like Clang's `scan-build`, `format`, and `tidy`. These functions generate Ninja rules to run these tools on the codebase.
    *   **Relevance to Reverse Engineering:** While not direct reverse engineering, these tools help find potential bugs and vulnerabilities in the code, which might be targets of reverse engineering efforts.
    *   **User Interaction:** These rules are created and can be executed if the user has the corresponding tools installed.

10. **`generate_tags(self, tool, target_name)`:**
    *   **Function:** Generates tags files for code navigation tools like `etags`, `ctags`, and `cscope`.
    *   **User Interaction:** These rules can be executed to generate tags files for easier code navigation.

11. **`generate_utils(self)`:**
    *   **Function:** Groups together various utility targets like running static analysis and the `uninstall` target.
    *   **User Interaction:** Provides a convenient way to execute common development tasks.

12. **`generate_ending(self)`:**
    *   **Function:** Generates the final "meta" targets in the `build.ninja` file, including `all` (the default target), `clean`, and `reconfigure`.
    *   **User Interaction:** This defines the behavior of common Ninja commands like `ninja` (builds the `all` target) and `ninja clean`.

13. **`get_introspection_data(self, target_id, target)`:**
    *   **Function:** Provides data for Meson's introspection API, allowing tools to query information about the build setup.

14. **`_scan_fortran_file_deps(src, srcdir, dirname, tdeps, compiler)`:**
    *   **Function:** Specifically scans Fortran source files for dependencies by looking for `include`, `use`, and `submodule` statements.
    *   **Logic/Assumptions:**  Relies on regular expressions to parse Fortran code. It makes assumptions about the formatting of these statements.

**User Operations and Debugging:**

A user's actions leading to this code being executed typically involve the following steps:

1. **Running `meson <source_dir> <build_dir>`:** This command initializes the Meson build system. During this process, Meson reads the `meson.build` files and constructs an internal representation of the project's build structure.
2. **Meson chooses the Ninja backend:**  Unless explicitly specified otherwise, Meson often defaults to the Ninja backend.
3. **The `NinjaBackend` class is instantiated:**  Meson creates an instance of the `NinjaBackend` class to handle the generation of the `build.ninja` file.
4. **Various `generate_*` methods are called:**  The `NinjaBackend` instance iterates through the build targets and other information from the Meson project description and calls the appropriate `generate_*` methods (like `generate_link`, `generate_prelink`, etc.) to create the corresponding Ninja rules.
5. **The `build.ninja` file is written:** The accumulated Ninja rules are written to the `build.ninja` file in the build directory.

**As a debugging线索 (debugging clue):**

If there are issues with the generated `build.ninja` file (e.g., incorrect compiler or linker flags, missing dependencies), inspecting the output of this Python code or setting breakpoints within it can help diagnose the problem. This is especially useful when:

*   **Linker errors occur:** Examining the generated linker commands can reveal incorrect library paths or missing libraries.
*   **Build dependencies are not being resolved correctly:**  Analyzing how dependencies are handled in `generate_link` can pinpoint issues.
*   **Custom build steps are failing:**  Looking at the commands generated by methods like `generate_custom_target_clean` can help understand the problem.

**Summary of Functionality:**

In essence, `ninjabackend.py` acts as a **translator** within the Meson build system. It takes the high-level build description provided in `meson.build` files and converts it into the low-level instructions understood by the Ninja build system. This involves generating specific commands for compiling, linking, and performing other build-related tasks, while also handling dependencies and user-specified options. It's a crucial component for enabling fast and efficient builds using Ninja.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
[:]
        cmd += prelinker.get_prelink_args(prelink_name, obj_list)

        cmd = self.replace_paths(target, cmd)
        elem.add_item('COMMAND', cmd)
        elem.add_item('description', f'Prelinking {prelink_name}.')
        self.add_build(elem)
        return [prelink_name]

    def generate_link(self, target: build.BuildTarget, outname, obj_list, linker: T.Union['Compiler', 'StaticLinker'], extra_args=None, stdlib_args=None):
        extra_args = extra_args if extra_args is not None else []
        stdlib_args = stdlib_args if stdlib_args is not None else []
        implicit_outs = []
        if isinstance(target, build.StaticLibrary):
            linker_base = 'STATIC'
        else:
            linker_base = linker.get_language() # Fixme.
        if isinstance(target, build.SharedLibrary):
            self.generate_shsym(target)
        crstr = self.get_rule_suffix(target.for_machine)
        linker_rule = linker_base + '_LINKER' + crstr
        # Create an empty commands list, and start adding link arguments from
        # various sources in the order in which they must override each other
        # starting from hard-coded defaults followed by build options and so on.
        #
        # Once all the linker options have been passed, we will start passing
        # libraries and library paths from internal and external sources.
        commands = linker.compiler_args()
        # First, the trivial ones that are impossible to override.
        #
        # Add linker args for linking this target derived from 'base' build
        # options passed on the command-line, in default_options, etc.
        # These have the lowest priority.
        if isinstance(target, build.StaticLibrary):
            commands += linker.get_base_link_args(target.get_options())
        else:
            commands += compilers.get_base_link_args(target.get_options(),
                                                     linker,
                                                     isinstance(target, build.SharedModule),
                                                     self.environment.get_build_dir())
        # Add -nostdlib if needed; can't be overridden
        commands += self.get_no_stdlib_link_args(target, linker)
        # Add things like /NOLOGO; usually can't be overridden
        commands += linker.get_linker_always_args()
        # Add buildtype linker args: optimization level, etc.
        commands += linker.get_optimization_link_args(target.get_option(OptionKey('optimization')))
        # Add /DEBUG and the pdb filename when using MSVC
        if target.get_option(OptionKey('debug')):
            commands += self.get_link_debugfile_args(linker, target)
            debugfile = self.get_link_debugfile_name(linker, target)
            if debugfile is not None:
                implicit_outs += [debugfile]
        # Add link args specific to this BuildTarget type, such as soname args,
        # PIC, import library generation, etc.
        commands += self.get_target_type_link_args(target, linker)
        # Archives that are copied wholesale in the result. Must be before any
        # other link targets so missing symbols from whole archives are found in those.
        if not isinstance(target, build.StaticLibrary):
            commands += self.get_link_whole_args(linker, target)

        if not isinstance(target, build.StaticLibrary):
            # Add link args added using add_project_link_arguments()
            commands += self.build.get_project_link_args(linker, target.subproject, target.for_machine)
            # Add link args added using add_global_link_arguments()
            # These override per-project link arguments
            commands += self.build.get_global_link_args(linker, target.for_machine)
            # Link args added from the env: LDFLAGS. We want these to override
            # all the defaults but not the per-target link args.
            commands += self.environment.coredata.get_external_link_args(target.for_machine, linker.get_language())

        # Now we will add libraries and library paths from various sources

        # Set runtime-paths so we can run executables without needing to set
        # LD_LIBRARY_PATH, etc in the environment. Doesn't work on Windows.
        if has_path_sep(target.name):
            # Target names really should not have slashes in them, but
            # unfortunately we did not check for that and some downstream projects
            # now have them. Once slashes are forbidden, remove this bit.
            target_slashname_workaround_dir = os.path.join(
                os.path.dirname(target.name),
                self.get_target_dir(target))
        else:
            target_slashname_workaround_dir = self.get_target_dir(target)
        (rpath_args, target.rpath_dirs_to_remove) = (
            linker.build_rpath_args(self.environment,
                                    self.environment.get_build_dir(),
                                    target_slashname_workaround_dir,
                                    self.determine_rpath_dirs(target),
                                    target.build_rpath,
                                    target.install_rpath))
        commands += rpath_args

        # Add link args to link to all internal libraries (link_with:) and
        # internal dependencies needed by this target.
        if linker_base == 'STATIC':
            # Link arguments of static libraries are not put in the command
            # line of the library. They are instead appended to the command
            # line where the static library is used.
            dependencies = []
        else:
            dependencies = target.get_dependencies()
        internal = self.build_target_link_arguments(linker, dependencies)
        commands += internal
        # Only non-static built targets need link args and link dependencies
        if not isinstance(target, build.StaticLibrary):
            # For 'automagic' deps: Boost and GTest. Also dependency('threads').
            # pkg-config puts the thread flags itself via `Cflags:`

            commands += linker.get_target_link_args(target)
            # External deps must be last because target link libraries may depend on them.
            for dep in target.get_external_deps():
                # Extend without reordering or de-dup to preserve `-L -l` sets
                # https://github.com/mesonbuild/meson/issues/1718
                commands.extend_preserving_lflags(linker.get_dependency_link_args(dep))
            for d in target.get_dependencies():
                if isinstance(d, build.StaticLibrary):
                    for dep in d.get_external_deps():
                        commands.extend_preserving_lflags(linker.get_dependency_link_args(dep))

        # Add link args specific to this BuildTarget type that must not be overridden by dependencies
        commands += self.get_target_type_link_args_post_dependencies(target, linker)

        # Add link args for c_* or cpp_* build options. Currently this only
        # adds c_winlibs and cpp_winlibs when building for Windows. This needs
        # to be after all internal and external libraries so that unresolved
        # symbols from those can be found here. This is needed when the
        # *_winlibs that we want to link to are static mingw64 libraries.
        if isinstance(linker, Compiler):
            # The static linker doesn't know what language it is building, so we
            # don't know what option. Fortunately, it doesn't care to see the
            # language-specific options either.
            #
            # We shouldn't check whether we are making a static library, because
            # in the LTO case we do use a real compiler here.
            commands += linker.get_option_link_args(target.get_options())

        dep_targets = []
        dep_targets.extend(self.guess_external_link_dependencies(linker, target, commands, internal))

        # Add libraries generated by custom targets
        custom_target_libraries = self.get_custom_target_provided_libraries(target)
        commands += extra_args
        commands += custom_target_libraries
        commands += stdlib_args # Standard library arguments go last, because they never depend on anything.
        dep_targets.extend([self.get_dependency_filename(t) for t in dependencies])
        dep_targets.extend([self.get_dependency_filename(t)
                            for t in target.link_depends])
        elem = NinjaBuildElement(self.all_outputs, outname, linker_rule, obj_list, implicit_outs=implicit_outs)
        elem.add_dep(dep_targets + custom_target_libraries)
        elem.add_item('LINK_ARGS', commands)
        self.create_target_linker_introspection(target, linker, commands)
        return elem

    def get_dependency_filename(self, t):
        if isinstance(t, build.SharedLibrary):
            return self.get_target_shsym_filename(t)
        elif isinstance(t, mesonlib.File):
            if t.is_built:
                return t.relative_name()
            else:
                return t.absolute_path(self.environment.get_source_dir(),
                                       self.environment.get_build_dir())
        return self.get_target_filename(t)

    def generate_shlib_aliases(self, target, outdir):
        for alias, to, tag in target.get_aliases():
            aliasfile = os.path.join(outdir, alias)
            abs_aliasfile = os.path.join(self.environment.get_build_dir(), outdir, alias)
            try:
                os.remove(abs_aliasfile)
            except Exception:
                pass
            try:
                os.symlink(to, abs_aliasfile)
            except NotImplementedError:
                mlog.debug("Library versioning disabled because symlinks are not supported.")
            except OSError:
                mlog.debug("Library versioning disabled because we do not have symlink creation privileges.")
            else:
                self.implicit_meson_outs.append(aliasfile)

    def generate_custom_target_clean(self, trees: T.List[str]) -> str:
        e = self.create_phony_target('clean-ctlist', 'CUSTOM_COMMAND', 'PHONY')
        d = CleanTrees(self.environment.get_build_dir(), trees)
        d_file = os.path.join(self.environment.get_scratch_dir(), 'cleantrees.dat')
        e.add_item('COMMAND', self.environment.get_build_command() + ['--internal', 'cleantrees', d_file])
        e.add_item('description', 'Cleaning custom target directories')
        self.add_build(e)
        # Write out the data file passed to the script
        with open(d_file, 'wb') as ofile:
            pickle.dump(d, ofile)
        return 'clean-ctlist'

    def generate_gcov_clean(self) -> None:
        gcno_elem = self.create_phony_target('clean-gcno', 'CUSTOM_COMMAND', 'PHONY')
        gcno_elem.add_item('COMMAND', mesonlib.get_meson_command() + ['--internal', 'delwithsuffix', '.', 'gcno'])
        gcno_elem.add_item('description', 'Deleting gcno files')
        self.add_build(gcno_elem)

        gcda_elem = self.create_phony_target('clean-gcda', 'CUSTOM_COMMAND', 'PHONY')
        gcda_elem.add_item('COMMAND', mesonlib.get_meson_command() + ['--internal', 'delwithsuffix', '.', 'gcda'])
        gcda_elem.add_item('description', 'Deleting gcda files')
        self.add_build(gcda_elem)

    def get_user_option_args(self):
        cmds = []
        for (k, v) in self.environment.coredata.options.items():
            if k.is_project():
                cmds.append('-D' + str(k) + '=' + (v.value if isinstance(v.value, str) else str(v.value).lower()))
        # The order of these arguments must be the same between runs of Meson
        # to ensure reproducible output. The order we pass them shouldn't
        # affect behavior in any other way.
        return sorted(cmds)

    def generate_dist(self) -> None:
        elem = self.create_phony_target('dist', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('DESC', 'Creating source packages')
        elem.add_item('COMMAND', self.environment.get_build_command() + ['dist'])
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_scanbuild(self) -> None:
        if not environment.detect_scanbuild():
            return
        if 'scan-build' in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'scanbuild', self.environment.source_dir, self.environment.build_dir, self.build.get_subproject_dir()] + \
            self.environment.get_build_command() + ['setup'] + self.get_user_option_args()
        elem = self.create_phony_target('scan-build', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_clangtool(self, name: str, extra_arg: T.Optional[str] = None) -> None:
        target_name = 'clang-' + name
        extra_args = []
        if extra_arg:
            target_name += f'-{extra_arg}'
            extra_args.append(f'--{extra_arg}')
        if not os.path.exists(os.path.join(self.environment.source_dir, '.clang-' + name)) and \
                not os.path.exists(os.path.join(self.environment.source_dir, '_clang-' + name)):
            return
        if target_name in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'clang' + name, self.environment.source_dir, self.environment.build_dir] + \
            extra_args
        elem = self.create_phony_target(target_name, 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_clangformat(self) -> None:
        if not environment.detect_clangformat():
            return
        self.generate_clangtool('format')
        self.generate_clangtool('format', 'check')

    def generate_clangtidy(self) -> None:
        import shutil
        if not shutil.which('clang-tidy'):
            return
        self.generate_clangtool('tidy')
        self.generate_clangtool('tidy', 'fix')

    def generate_tags(self, tool: str, target_name: str) -> None:
        import shutil
        if not shutil.which(tool):
            return
        if target_name in self.all_outputs:
            return
        cmd = self.environment.get_build_command() + \
            ['--internal', 'tags', tool, self.environment.source_dir]
        elem = self.create_phony_target(target_name, 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    # For things like scan-build and other helper tools we might have.
    def generate_utils(self) -> None:
        self.generate_scanbuild()
        self.generate_clangformat()
        self.generate_clangtidy()
        self.generate_tags('etags', 'TAGS')
        self.generate_tags('ctags', 'ctags')
        self.generate_tags('cscope', 'cscope')
        cmd = self.environment.get_build_command() + ['--internal', 'uninstall']
        elem = self.create_phony_target('uninstall', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', cmd)
        elem.add_item('pool', 'console')
        self.add_build(elem)

    def generate_ending(self) -> None:
        for targ, deps in [
                ('all', self.get_build_by_default_targets()),
                ('meson-test-prereq', self.get_testlike_targets()),
                ('meson-benchmark-prereq', self.get_testlike_targets(True))]:
            targetlist = []
            # These must also be built by default.
            # XXX: Sometime in the future these should be built only before running tests.
            if targ == 'all':
                targetlist.extend(['meson-test-prereq', 'meson-benchmark-prereq'])
            for t in deps.values():
                # Add the first output of each target to the 'all' target so that
                # they are all built
                #Add archive file if shared library in AIX for build all.
                if isinstance(t, build.SharedLibrary) and t.aix_so_archive:
                    if self.environment.machines[t.for_machine].is_aix():
                        linker, stdlib_args = self.determine_linker_and_stdlib_args(t)
                        t.get_outputs()[0] = linker.get_archive_name(t.get_outputs()[0])
                targetlist.append(os.path.join(self.get_target_dir(t), t.get_outputs()[0]))

            elem = NinjaBuildElement(self.all_outputs, targ, 'phony', targetlist)
            self.add_build(elem)

        elem = self.create_phony_target('clean', 'CUSTOM_COMMAND', 'PHONY')
        elem.add_item('COMMAND', self.ninja_command + ['-t', 'clean'])
        elem.add_item('description', 'Cleaning')

        # If we have custom targets in this project, add all their outputs to
        # the list that is passed to the `cleantrees.py` script. The script
        # will manually delete all custom_target outputs that are directories
        # instead of files. This is needed because on platforms other than
        # Windows, Ninja only deletes directories while cleaning if they are
        # empty. https://github.com/mesonbuild/meson/issues/1220
        ctlist = []
        for t in self.build.get_targets().values():
            if isinstance(t, build.CustomTarget):
                # Create a list of all custom target outputs
                for o in t.get_outputs():
                    ctlist.append(os.path.join(self.get_target_dir(t), o))
        if ctlist:
            elem.add_dep(self.generate_custom_target_clean(ctlist))

        if OptionKey('b_coverage') in self.environment.coredata.options and \
           self.environment.coredata.options[OptionKey('b_coverage')].value:
            self.generate_gcov_clean()
            elem.add_dep('clean-gcda')
            elem.add_dep('clean-gcno')
        self.add_build(elem)

        deps = self.get_regen_filelist()
        elem = NinjaBuildElement(self.all_outputs, 'build.ninja', 'REGENERATE_BUILD', deps)
        elem.add_item('pool', 'console')
        self.add_build(elem)

        # If these files used to be explicitly created, they need to appear on the build graph somehow,
        # otherwise cleandead deletes them. See https://github.com/ninja-build/ninja/issues/2299
        if self.implicit_meson_outs:
            elem = NinjaBuildElement(self.all_outputs, 'meson-implicit-outs', 'phony', self.implicit_meson_outs)
            self.add_build(elem)

        elem = NinjaBuildElement(self.all_outputs, 'reconfigure', 'REGENERATE_BUILD', 'PHONY')
        elem.add_item('pool', 'console')
        self.add_build(elem)

        elem = NinjaBuildElement(self.all_outputs, deps, 'phony', '')
        self.add_build(elem)

    def get_introspection_data(self, target_id: str, target: build.Target) -> T.List[T.Dict[str, T.Union[bool, str, T.List[T.Union[str, T.Dict[str, T.Union[str, T.List[str], bool]]]]]]]:
        data = self.introspection_data.get(target_id)
        if not data:
            return super().get_introspection_data(target_id, target)

        return list(data.values())


def _scan_fortran_file_deps(src: Path, srcdir: Path, dirname: Path, tdeps, compiler) -> T.List[str]:
    """
    scan a Fortran file for dependencies. Needs to be distinct from target
    to allow for recursion induced by `include` statements.er

    It makes a number of assumptions, including

    * `use`, `module`, `submodule` name is not on a continuation line

    Regex
    -----

    * `incre` works for `#include "foo.f90"` and `include "foo.f90"`
    * `usere` works for legacy and Fortran 2003 `use` statements
    * `submodre` is for Fortran >= 2008 `submodule`
    """

    incre = re.compile(FORTRAN_INCLUDE_PAT, re.IGNORECASE)
    usere = re.compile(FORTRAN_USE_PAT, re.IGNORECASE)
    submodre = re.compile(FORTRAN_SUBMOD_PAT, re.IGNORECASE)

    mod_files = []
    src = Path(src)
    with src.open(encoding='ascii', errors='ignore') as f:
        for line in f:
            # included files
            incmatch = incre.match(line)
            if incmatch is not None:
                incfile = src.parent / incmatch.group(1)
                # NOTE: src.parent is most general, in particular for CMake subproject with Fortran file
                # having an `include 'foo.f'` statement.
                if incfile.suffix.lower()[1:] in compiler.file_suffixes:
                    mod_files.extend(_scan_fortran_file_deps(incfile, srcdir, dirname, tdeps, compiler))
            # modules
            usematch = usere.match(line)
            if usematch is not None:
                usename = usematch.group(1).lower()
                if usename == 'intrinsic':  # this keeps the regex simpler
                    continue
                if usename not in tdeps:
                    # The module is not provided by any source file. This
                    # is due to:
                    #   a) missing file/typo/etc
                    #   b) using a module provided by the compiler, such as
                    #      OpenMP
                    # There's no easy way to tell which is which (that I
                    # know of) so just ignore this and go on. Ideally we
                    # would print a warning message to the user but this is
                    # a common occurrence, which would lead to lots of
                    # distracting noise.
                    continue
                srcfile = srcdir / tdeps[usename].fname
                if not srcfile.is_file():
                    if srcfile.name != src.name:  # generated source file
                        pass
                    else:  # subproject
                        continue
                elif srcfile.samefile(src):  # self-reference
                    continue

                mod_name = compiler.module_name_to_filename(usename)
                mod_files.append(str(dirname / mod_name))
            else:  # submodules
                submodmatch = submodre.match(line)
                if submodmatch is not None:
                    parents = submodmatch.group(1).lower().split(':')
                    assert len(parents) in {1, 2}, (
                        'submodule ancestry must be specified as'
                        f' ancestor:parent but Meson found {parents}')

                    ancestor_child = '_'.join(parents)
                    if ancestor_child not in tdeps:
                        raise MesonException("submodule {} relies on ancestor module {} that was not found.".format(submodmatch.group(2).lower(), ancestor_child.split('_', maxsplit=1)[0]))
                    submodsrcfile = srcdir / tdeps[ancestor_child].fname
                    if not submodsrcfile.is_file():
                        if submodsrcfile.name != src.name:  # generated source file
                            pass
                        else:  # subproject
                            continue
                    elif submodsrcfile.samefile(src):  # self-reference
                        continue
                    mod_name = compiler.module_name_to_filename(ancestor_child)
                    mod_files.append(str(dirname / mod_name))
    return mod_files
```