Response:
The user wants a summary of the `ninjabackend.py` file's functionalities, focusing on its relevance to reverse engineering, binary/kernel interactions, logical inferences, common user errors, and debugging steps.

Here's a breakdown of how to approach this:

1. **Understand the file's purpose:** The file is part of Meson, a build system, specifically the Ninja backend. This means it's responsible for translating Meson's build description into Ninja build files.

2. **Identify key functionalities:** Scan the code for methods and their actions. Look for patterns like:
    - Generating commands (`cmd += ...`)
    - Creating build rules (`self.add_build(...)`)
    - Handling different target types (e.g., static/shared libraries, executables)
    - Dealing with dependencies
    - Managing compiler and linker flags

3. **Relate to reverse engineering:** Consider how the generated build process can be influenced or observed during reverse engineering. Think about:
    - Linker flags and their effect on the final binary (e.g., stripping symbols, setting RPATH).
    - The structure of the build process and how it might reveal information about the target.

4. **Connect to binary/kernel/framework:**  Look for code dealing with:
    - Linking (which produces binary executables and libraries).
    - Concepts like RPATH (important for runtime library loading in Linux).
    - Shared libraries and their symbols.
    - Interactions with the operating system's build tools.

5. **Analyze logical inferences:** Identify areas where the code makes decisions based on input, and try to formulate "if-then" scenarios.

6. **Anticipate user errors:** Think about common mistakes users make when defining their builds in Meson that could lead to specific outcomes in this backend.

7. **Trace user operations:**  Consider the high-level steps a user takes when using Meson, leading up to the execution of this code.

8. **Synthesize the summary:** Combine the findings from the previous steps into a concise overview of the file's role and key features.
This Python code snippet is a part of the Ninja backend for the Meson build system. It's specifically responsible for generating the Ninja build file content related to *linking* different types of build targets (executables, static libraries, shared libraries, shared modules) and some auxiliary tasks like prelinking.

Here's a breakdown of its functionalities:

**Core Linking Functionalities:**

* **`generate_prelink(self, target, obj_list, prelinker)`:** Generates the Ninja command to perform prelinking. Prelinking is an optimization technique that resolves symbolic links within object files before the final linking stage.
    * **Function:**  Optimizes the linking process, potentially speeding up final linking and reducing the size of the final binary.
    * **Binary 底层:** Prelinking manipulates the internal structure of object files and how they are linked together.
    * **Linux:** Prelinking is more common on Linux-based systems.
    * **逻辑推理 (Hypothetical Input & Output):**
        * **Input:** A shared library target (`target`), a list of its object files (`obj_list`), and the prelinker tool (`prelinker`).
        * **Output:** A Ninja build rule that executes the prelinker command on the object files, resulting in a prelinked object file (`prelink_name`).

* **`generate_link(self, target, outname, obj_list, linker, extra_args=None, stdlib_args=None)`:**  The core function for generating Ninja commands to link build targets. It handles various aspects of linking, including:
    * Determining the linker rule based on the target type (static library, shared library/module, executable).
    * Adding compiler and linker arguments from various sources (base options, build type, debug settings, target-specific flags, project/global link arguments, environment variables).
    * Handling runtime paths (RPATH) for finding shared libraries at runtime (primarily on Linux).
    * Linking internal libraries and external dependencies.
    * Handling library versioning and aliases for shared libraries.
    * **Function:** Creates the final executable or library binary by combining object files and linking against necessary libraries.
    * **逆向方法:**  The linker flags used here significantly impact the final binary. For example:
        * `-s` or similar flags strip symbols, making reverse engineering harder.
        * Debug information (`-g`, `/DEBUG`) makes debugging and reverse engineering easier.
        * RPATH settings determine where the program looks for shared libraries, which is important for understanding dependencies.
    * **二进制底层:** This function directly interacts with the linker, a crucial part of the binary creation process. It dictates how code and data sections from different object files are combined and how external symbols are resolved.
    * **Linux:** RPATH handling is a Linux-specific feature.
    * **Android:** Similar concepts exist on Android, though the specific mechanisms might differ.
    * **逻辑推理 (Hypothetical Input & Output):**
        * **Input:**  An executable target (`target`), the output filename (`outname`), a list of object files (`obj_list`), the linker (`linker`), and potentially extra linker flags (`extra_args`).
        * **Output:** A Ninja build rule that executes the linker command with the specified object files and flags, producing the final executable binary. The rule also includes dependencies on the object files.

* **`get_dependency_filename(self, t)`:** Returns the filename of a dependency, handling different dependency types (shared libraries, built files, source files).
    * **Function:**  Ensures correct dependency tracking in the Ninja build file.
    * **二进制底层:** For shared libraries, it might return the symbolic link to the actual shared library file, reflecting the versioning scheme.

* **`generate_shlib_aliases(self, target, outdir)`:** Creates symbolic links for shared library aliases (e.g., versioned shared libraries).
    * **Function:** Enables library versioning, allowing multiple versions of a library to coexist.
    * **二进制底层:** Symbolic links are a fundamental filesystem concept in Unix-like systems, crucial for dynamic linking and library management.
    * **Linux/Android:** Library versioning and symbolic links are common practices on these platforms.

**Auxiliary Functionalities:**

* **`generate_custom_target_clean(self, trees)`:** Generates a Ninja command to clean the output directories of custom targets.
    * **Function:**  Provides a mechanism to clean up files generated by user-defined custom build steps.
* **`generate_gcov_clean(self)`:** Generates Ninja commands to clean up `gcno` and `gcda` files (used for code coverage analysis with gcov).
    * **Function:**  Facilitates cleaning up coverage data.
* **`get_user_option_args(self)`:**  Retrieves user-defined options as command-line arguments for Meson.
* **`generate_dist(self)`:** Generates a Ninja command to create source packages for distribution.
* **`generate_scanbuild(self)`:** Generates a Ninja command to run `scan-build` (a static analysis tool).
* **`generate_clangtool(self, name, extra_arg=None)`:**  A helper for generating Ninja commands to run clang-related tools like `clang-format` and `clang-tidy`.
* **`generate_clangformat(self)`:** Generates Ninja commands for `clang-format`.
* **`generate_clangtidy(self)`:** Generates Ninja commands for `clang-tidy`.
* **`generate_tags(self, tool, target_name)`:** Generates Ninja commands for generating code tags (like with `etags`, `ctags`).
* **`generate_utils(self)`:** Groups the generation of various utility commands.
* **`generate_ending(self)`:** Generates the final parts of the Ninja build file, including the default target (`all`), the `clean` target, and the rule to regenerate the build file itself.

**Relationship to Reverse Engineering:**

As mentioned with `generate_link`, the linker flags and the structure of the build process revealed by the generated Ninja file can provide valuable insights during reverse engineering. Understanding how a binary was built can help in:

* **Identifying compiler and linker used:** This might hint at potential optimizations or security features.
* **Discovering linked libraries:**  Essential for understanding dependencies and potential vulnerabilities.
* **Analyzing symbol stripping:** Knowing if symbols are present or stripped affects the complexity of static analysis.
* **Understanding runtime library paths:** Crucial for debugging and analyzing library loading behavior.

**User/Programming Common Usage Errors (and how they might lead here):**

* **Incorrectly specified dependencies:** If a user forgets to specify a required library dependency in their `meson.build` file, the linker command generated by `generate_link` might be missing the `-l` flag for that library, leading to linker errors.
* **Conflicting linker flags:** Users might accidentally specify conflicting linker flags, which Meson tries to resolve based on priority, but could still lead to unexpected linking behavior.
* **Incorrect RPATH settings:**  Manually setting incorrect RPATH values in `meson.build` can lead to runtime library loading issues.
* **Problems with custom targets:** If a custom target doesn't produce the expected output, it can break the dependency chain and lead to linking failures.

**User Operation Steps to Reach This Code:**

1. **User writes `meson.build` files:**  They define their project's build structure, including targets, dependencies, and compiler/linker options.
2. **User runs `meson setup builddir`:** Meson reads the `meson.build` files and configures the build environment.
3. **Meson selects the Ninja backend:** Based on the user's system or explicitly chosen backend.
4. **Meson translates the build definition:** The Ninja backend's classes, including `NinjaBackend`, are used to convert the abstract build description into concrete Ninja rules.
5. **Specifically, when a library or executable target needs to be linked:** The `generate_link` method in `ninjabackend.py` is called with the relevant target information.
6. **When prelinking is enabled for a target:** The `generate_prelink` method is invoked.
7. **When cleaning the build directory:** The `generate_custom_target_clean` and `generate_gcov_clean` methods might be used.

**归纳一下它的功能 (Summary of its function):**

This code file (`ninjabackend.py`) within the Frida project's build system (Meson with Ninja backend) is responsible for **generating the Ninja build rules specifically related to the linking process of various software components (executables, static and shared libraries).** It takes the abstract build definitions from Meson and translates them into concrete Ninja commands that invoke the compiler and linker with the correct object files, libraries, and flags. It also handles supplementary tasks like prelinking, shared library versioning, and generating rules for cleaning and other utility functions. Essentially, it bridges the gap between a high-level build description and the low-level commands needed to create the final binary artifacts.

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/backend/ninjabackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能

"""
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

"""


```