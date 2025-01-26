响应:

```
嗯，我现在需要分析这个Rust代码，看看它属于APatch项目的哪个部分，并且列举出它的功能步骤。首先，我得先理解整个项目的作用。APatch是一个基于内核的Android root解决方案，类似于Magisk，但支持内核模块注入。这段代码在module.rs里，应该跟模块管理有关。

代码里有很多函数，比如exec_install_script、install_module、uninstall_module、enable/disable_module等。看起来主要是处理模块的安装、卸载、启用、禁用，以及执行相关脚本。可能涉及到文件操作、权限设置、SELinux策略加载等。

让我先看看每个函数的大致作用。例如，exec_install_script函数里调用了BusyBox执行安装脚本，设置了一些环境变量，比如APATCH版本信息，还处理了模块的路径。安装模块的函数_install_module会检查系统是否启动完成，解压模块文件，处理module.prop，设置权限和SELinux上下文，然后执行安装脚本，最后标记更新。

卸载模块的时候，会找到对应的模块目录，创建.remove文件，可能在下一次启动时清理。启用和禁用模块则是通过创建或删除.disable文件来控制模块状态。还有加载sepolicy规则、执行各个阶段的脚本（比如post-fs-data、boot-completed）、处理系统属性等。

步骤方面，可能的执行顺序是：安装模块时先检查系统是否完成启动，解压模块文件，设置权限，执行安装脚本，然后标记需要更新。在系统启动的不同阶段，比如post-fs阶段，加载模块的sepolicy规则，执行模块的启动脚本，设置系统属性。模块的启用和禁用通过文件标记，后台可能有进程定期清理已标记删除的模块。

生成的外部痕迹可能包括模块目录下的各种文件，比如在/data/adb/modules下的各个模块目录，安装的脚本、prop文件，或者日志文件。还有可能修改系统属性，或者加载的内核模块痕迹。

比如用shell命令安装模块的话，可能类似于apatch install module.zip，内部会调用busybox执行安装脚本。查看已安装模块可能通过apatch list-modules，返回JSON格式的信息。

现在需要把这些步骤按顺序整理出来，大概分为安装、启用、执行脚本、加载策略、清理模块等步骤。同时考虑启动时的处理，比如在boot完成后才能安装模块，或者在启动的不同阶段执行对应的脚本。
```
根据代码逻辑，推测module.rs的主要功能是管理APatch模块的安装、卸载、状态切换及策略加载。以下是可能的执行顺序：

10个核心功能步骤：
1. 系统启动后检查boot_completed状态
2. 安装模块时验证模块ID并解压到指定目录
3. 设置模块目录权限和SELinux上下文
4. 执行模块的install.sh安装脚本
5. 标记模块需要更新（创建.update文件）
6. 加载模块的sepolicy.rule安全策略
7. 在post-fs/boot阶段执行模块对应脚本
8. 处理系统属性修改（通过system.prop）
9. 根据标记文件清理待删除模块
10. 通过.disable文件控制模块启用状态

功能实现推理示例（Shell模拟）：
```bash
# 安装模块
APATCH_BIN install module.zip

# 内部操作模拟：
# 1. 解压module.prop获取模块ID
unzip -p module.zip module.prop > /tmp/module.prop
id=$(grep 'id=' /tmp/module.prop | cut -d= -f2)

# 2. 创建模块目录
mkdir -p /data/adb/apatch/modules/$id

# 3. 执行安装脚本
busybox sh -c "$(unzip -p module.zip installer.sh)" \
  APATCH_VER=1.0 ZIPFILE=$(realpath module.zip)

# 4. 标记更新
touch /data/adb/apatch/modules/$id/.update
```

输入输出示例：
假设输入模块包含：
```
module.prop内容：
id=example_module
version=1.0

installer.sh内容：
echo "Installing module..."
```

输出结果：
```
创建目录：/data/adb/apatch/modules/example_module
设置权限：700
生成标记文件：.update
系统日志记录策略加载
```

文件系统访问细节：
1. 模块存储路径：
   - 激活模块：/data/adb/apatch/modules/<id>
   - 临时目录：/data/adb/apatch/modules_update_tmp/<id>
2. 关键标记文件：
   - .disable：禁用状态标记
   - .remove：待删除标记
   - .update：需要更新标记
3. 脚本执行路径：
   - post-fs-data.sh：早期启动阶段执行
   - boot-completed.sh：系统启动完成后执行

外部可见痕迹：
1. 文件系统痕迹：
   ```bash
   /data/adb/apatch/modules/* # 模块存储目录
   /proc/mounts | grep apatch # 挂载点信息
   ```

2. 进程痕迹：
   ```bash
   ps -A | grep -E 'busybox|magiskpolicy' # 子进程活动
   ```

3. 系统属性：
   ```bash
   getprop | grep apatch # 环境变量注入
   ```

4. SELinux策略：
   ```bash
   seinfo -r | grep apatch_ # 加载的自定义规则
   ```

代码特征分析：
1. 模块生命周期管理：通过标记文件实现原子操作
2. 安全策略实施：使用magiskpolicy加载规则
3. 兼容性处理：同时支持overlayfs和bind mount
4. 错误防御：严格检查文件权限和系统状态
5. 异步清理机制：通过标记文件延后删除操作

典型工作流程：
1. 用户执行模块安装命令
2. 验证系统状态和模块有效性
3. 解压模块并设置文件权限
4. 执行模块安装脚本
5. 创建状态标记文件
6. 系统下次启动时应用变更
7. 执行阶段脚本并加载策略
8. 定期清理被标记删除的模块
提示器:

这是路径为APatch/apd/src/module.rs的apatch `The patching of Android kernel and Android system`实现的一部分，
它的项目描述如下`
A new kernel-based root solution for Android devices.
APM: Support for modules similar to Magisk.
KPM: Support for modules that allow you to inject any code into the kernel (Provides kernel function inline-hook and syscall-table-hook).
APatch relies on KernelPatch.
The APatch UI and the APModule source code have been derived and modified from KernelSU.
` 
请按照最可能的执行顺序(非行号)列举一下它的功能, 建议10步，　
如果你能推理出它是什么功能的实现，请用shell代码举例, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，涉及到对文件系统的访问，请详细介绍一下，
如果这个程序生成了哪些android外部进程可以看到的痕迹，请提示一下，
请用中文回答。

```rust
#[allow(clippy::wildcard_imports)]
use crate::utils::*;
use crate::{assets, defs, restorecon, utils};
use anyhow::{anyhow, bail, ensure, Context, Result};
use const_format::concatcp;
use is_executable::is_executable;
use java_properties::PropertiesIter;
use log::{info, warn};
use regex_lite::Regex;
use std::{
    collections::HashMap,
    env::var as env_var,
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
};
use zip_extensions::zip_extract_file_to_memory;

#[cfg(unix)]
use std::os::unix::{prelude::PermissionsExt, process::CommandExt};

const INSTALLER_CONTENT: &str = include_str!("./installer.sh");
const INSTALLER_CONTENT_: &str = include_str!("./installer_bind.sh");
const INSTALL_MODULE_SCRIPT: &str = concatcp!(
    INSTALLER_CONTENT,
    "\n",
    "install_module",
    "\n",
    "exit 0",
    "\n"
);
const INSTALL_MODULE_SCRIPT_: &str = concatcp!(
    INSTALLER_CONTENT_,
    "\n",
    "install_module",
    "\n",
    "exit 0",
    "\n"
);

fn exec_install_script(module_file: &str) -> Result<()> {
    let realpath = std::fs::canonicalize(module_file)
        .with_context(|| format!("realpath: {module_file} failed"))?;

    let mut content;

    if !should_enable_overlay()? {
        content = INSTALL_MODULE_SCRIPT_.to_string();
    } else {
        content = INSTALL_MODULE_SCRIPT.to_string();
    }
    let result = Command::new(assets::BUSYBOX_PATH)
        .args(["sh", "-c", &content])
        .env("ASH_STANDALONE", "1")
        .env(
            "PATH",
            format!(
                "{}:{}",
                env_var("PATH").unwrap(),
                defs::BINARY_DIR.trim_end_matches('/')
            ),
        )
        .env("APATCH", "true")
        .env("APATCH_VER", defs::VERSION_NAME)
        .env("APATCH_VER_CODE", defs::VERSION_CODE)
        .env(
            "APATCH_BIND_MOUNT",
            format!("{}", !utils::should_enable_overlay()?),
        )
        .env("OUTFD", "1")
        .env("ZIPFILE", realpath)
        .status()?;
    ensure!(result.success(), "Failed to install module script");
    Ok(())
}

// becuase we use something like A-B update
// we need to update the module state after the boot_completed
// if someone(such as the module) install a module before the boot_completed
// then it may cause some problems, just forbid it
fn ensure_boot_completed() -> Result<()> {
    // ensure getprop sys.boot_completed == 1
    if getprop("sys.boot_completed").as_deref() != Some("1") {
        bail!("Android is Booting!");
    }
    Ok(())
}

fn mark_update() -> Result<()> {
    ensure_file_exists(concatcp!(defs::WORKING_DIR, defs::UPDATE_FILE_NAME))
}

fn mark_module_state(module: &str, flag_file: &str, create_or_delete: bool) -> Result<()> {
    let module_state_file = Path::new(defs::MODULE_DIR).join(module).join(flag_file);
    if create_or_delete {
        ensure_file_exists(module_state_file)
    } else {
        if module_state_file.exists() {
            std::fs::remove_file(module_state_file)?;
        }
        Ok(())
    }
}

fn foreach_module(active_only: bool, mut f: impl FnMut(&Path) -> Result<()>) -> Result<()> {
    let modules_dir = Path::new(defs::MODULE_DIR);
    let dir = std::fs::read_dir(modules_dir)?;
    for entry in dir.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            warn!("{} is not a directory, skip", path.display());
            continue;
        }

        if active_only && path.join(defs::DISABLE_FILE_NAME).exists() {
            info!("{} is disabled, skip", path.display());
            continue;
        }
        if active_only && path.join(defs::REMOVE_FILE_NAME).exists() {
            warn!("{} is removed, skip", path.display());
            continue;
        }

        f(&path)?;
    }

    Ok(())
}

fn foreach_active_module(f: impl FnMut(&Path) -> Result<()>) -> Result<()> {
    foreach_module(true, f)
}

pub fn check_image(img: &str) -> Result<()> {
    let result = Command::new("e2fsck")
        .args(["-yf", img])
        .stdout(Stdio::piped())
        .status()
        .with_context(|| format!("Failed to exec e2fsck {img}"))?;
    let code = result.code();
    // 0 or 1 is ok
    // 0: no error
    // 1: file system errors corrected
    // https://man7.org/linux/man-pages/man8/e2fsck.8.html
    // ensure!(
    //     code == Some(0) || code == Some(1),
    //     "Failed to check image, e2fsck exit code: {}",
    //     code.unwrap_or(-1)
    // );
    info!("e2fsck exit code: {}", code.unwrap_or(-1));
    Ok(())
}

pub fn load_sepolicy_rule() -> Result<()> {
    foreach_active_module(|path| {
        let rule_file = path.join("sepolicy.rule");
        if !rule_file.exists() {
            return Ok(());
        }

        info!("load policy: {}", &rule_file.display());
        Command::new(assets::MAGISKPOLICY_PATH)
            .arg("--live")
            .arg("--apply")
            .arg(&rule_file)
            .status()
            .with_context(|| format!("Failed to exec {}", rule_file.display()))?;
        Ok(())
    })?;

    Ok(())
}

fn exec_script<T: AsRef<Path>>(path: T, wait: bool) -> Result<()> {
    info!("exec {}", path.as_ref().display());

    let mut command = &mut Command::new(assets::BUSYBOX_PATH);
    #[cfg(unix)]
    {
        command = command.process_group(0);
        command = unsafe {
            command.pre_exec(|| {
                // ignore the error?
                switch_cgroups();
                Ok(())
            })
        };
    }
    command = command
        .current_dir(path.as_ref().parent().unwrap())
        .arg("sh")
        .arg(path.as_ref())
        .env("ASH_STANDALONE", "1")
        .env("APATCH", "true")
        .env("APATCH_VER", defs::VERSION_NAME)
        .env("APATCH_VER_CODE", defs::VERSION_CODE)
        .env(
            "APATCH_BIND_MOUNT",
            format!("{}", !utils::should_enable_overlay()?),
        )
        .env(
            "PATH",
            format!(
                "{}:{}",
                env_var("PATH").unwrap(),
                defs::BINARY_DIR.trim_end_matches('/')
            ),
        );

    let result = if wait {
        command.status().map(|_| ())
    } else {
        command.spawn().map(|_| ())
    };
    result.map_err(|err| anyhow!("Failed to exec {}: {}", path.as_ref().display(), err))
}

pub fn exec_stage_script(stage: &str, block: bool) -> Result<()> {
    foreach_active_module(|module| {
        let script_path = module.join(format!("{stage}.sh"));
        if !script_path.exists() {
            return Ok(());
        }

        exec_script(&script_path, block)
    })?;

    Ok(())
}

pub fn exec_common_scripts(dir: &str, wait: bool) -> Result<()> {
    let script_dir = Path::new(defs::ADB_DIR).join(dir);
    if !script_dir.exists() {
        info!("{} not exists, skip", script_dir.display());
        return Ok(());
    }

    let dir = std::fs::read_dir(&script_dir)?;
    for entry in dir.flatten() {
        let path = entry.path();

        if !is_executable(&path) {
            warn!("{} is not executable, skip", path.display());
            continue;
        }

        exec_script(path, wait)?;
    }

    Ok(())
}

pub fn load_system_prop() -> Result<()> {
    foreach_active_module(|module| {
        let system_prop = module.join("system.prop");
        if !system_prop.exists() {
            return Ok(());
        }
        info!("load {} system.prop", module.display());

        // resetprop -n --file system.prop
        Command::new(assets::RESETPROP_PATH)
            .arg("-n")
            .arg("--file")
            .arg(&system_prop)
            .status()
            .with_context(|| format!("Failed to exec {}", system_prop.display()))?;

        Ok(())
    })?;

    Ok(())
}

pub fn prune_modules() -> Result<()> {
    foreach_module(false, |module| {
        std::fs::remove_file(module.join(defs::UPDATE_FILE_NAME)).ok();
        if !module.join(defs::REMOVE_FILE_NAME).exists() {
            return Ok(());
        }

        info!("remove module: {}", module.display());

        let uninstaller = module.join("uninstall.sh");
        if uninstaller.exists() {
            if let Err(e) = exec_script(uninstaller, true) {
                warn!("Failed to exec uninstaller: {}", e);
            }
        }

        if let Err(e) = std::fs::remove_dir_all(module) {
            warn!("Failed to remove {}: {}", module.display(), e);
        }
        let module_path = module.display().to_string();
        let updated_path = module_path.replace(defs::MODULE_DIR, defs::MODULE_UPDATE_TMP_DIR);

        if let Err(e) = std::fs::remove_dir_all(&updated_path) {
            warn!("Failed to remove {}: {}", updated_path, e);
        }
        Ok(())
    })?;

    Ok(())
}

fn _install_module(zip: &str) -> Result<()> {
    ensure_boot_completed()?;

    // print banner
    println!(include_str!("banner"));

    assets::ensure_binaries().with_context(|| "binary missing")?;

    // first check if workding dir is usable
    ensure_dir_exists(defs::WORKING_DIR).with_context(|| "Failed to create working dir")?;
    ensure_dir_exists(defs::BINARY_DIR).with_context(|| "Failed to create bin dir")?;

    // read the module_id from zip, if faild if will return early.
    let mut buffer: Vec<u8> = Vec::new();
    let entry_path = PathBuf::from_str("module.prop")?;
    let zip_path = PathBuf::from_str(zip)?;
    let zip_path = zip_path.canonicalize()?;
    zip_extract_file_to_memory(&zip_path, &entry_path, &mut buffer)?;
    let mut module_prop = HashMap::new();
    PropertiesIter::new_with_encoding(Cursor::new(buffer), encoding_rs::UTF_8).read_into(
        |k, v| {
            module_prop.insert(k, v);
        },
    )?;
    info!("module prop: {:?}", module_prop);

    let Some(module_id) = module_prop.get("id") else {
        bail!("module id not found in module.prop!");
    };

    let modules_dir = Path::new(defs::MODULE_DIR);
    let modules_update_dir = Path::new(defs::MODULE_UPDATE_TMP_DIR);
    if !Path::new(modules_dir).exists() {
        fs::create_dir(modules_dir).expect("Failed to create modules folder");
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(modules_dir, permissions).expect("Failed to set permissions");
    }

    let module_dir = format!("{}{}", modules_dir.display(), module_id.clone());
    let module_update_dir = format!("{}{}", modules_update_dir.display(), module_id.clone());
    info!("module dir: {}", module_dir);
    if !Path::new(&module_dir.clone()).exists() {
        fs::create_dir(&module_dir.clone()).expect("Failed to create module folder");
        let permissions = fs::Permissions::from_mode(0o700);
        fs::set_permissions(module_dir.clone(), permissions).expect("Failed to set permissions");
    }
    // unzip the image and move it to modules_update/<id> dir
    let file = std::fs::File::open(zip)?;
    let mut archive = zip::ZipArchive::new(file)?;
    if should_enable_overlay()? {
        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let file_name = file.name().to_string();

            if file_name == "module.prop" {
                let output_path = Path::new(&module_dir).join(&file_name);
                let mut output_file = std::fs::File::create(&output_path)?;

                std::io::copy(&mut file, &mut output_file)?;
                println!("Extracted: {}", output_path.display());
            }
        }
    }

    // set permission and selinux context for $MOD/system
    let module_system_dir = PathBuf::from(module_dir.clone()).join("system");
    if module_system_dir.exists() {
        #[cfg(unix)]
        std::fs::set_permissions(&module_system_dir, std::fs::Permissions::from_mode(0o755))?;
        restorecon::restore_syscon(&module_system_dir)?;
    }
    exec_install_script(zip)?;
    mark_update()?;
    Ok(())
}

pub fn install_module(zip: &str) -> Result<()> {
    let result = _install_module(zip);
    result
}

pub fn _uninstall_module(id: &str, update_dir: &str) -> Result<()> {
    let dir = Path::new(update_dir);
    ensure!(dir.exists(), "No module installed");

    // iterate the modules_update dir, find the module to be removed
    let dir = std::fs::read_dir(dir)?;
    for entry in dir.flatten() {
        let path = entry.path();
        let module_prop = path.join("module.prop");
        if !module_prop.exists() {
            continue;
        }
        let content = std::fs::read(module_prop)?;
        let mut module_id: String = String::new();
        PropertiesIter::new_with_encoding(Cursor::new(content), encoding_rs::UTF_8).read_into(
            |k, v| {
                if k.eq("id") {
                    module_id = v;
                }
            },
        )?;
        if module_id.eq(id) {
            let remove_file = path.join(defs::REMOVE_FILE_NAME);
            fs::File::create(remove_file).with_context(|| "Failed to create remove file.")?;
            break;
        }
    }

    // santity check
    let target_module_path = format!("{update_dir}/{id}");
    let target_module = Path::new(&target_module_path);
    if target_module.exists() {
        let remove_file = target_module.join(defs::REMOVE_FILE_NAME);
        if !remove_file.exists() {
            fs::File::create(remove_file).with_context(|| "Failed to create remove file.")?;
        }
    }

    let _ = mark_module_state(id, defs::REMOVE_FILE_NAME, true);
    Ok(())
}
pub fn uninstall_module(id: &str) -> Result<()> {
    //let result = _uninstall_module(id, defs::MODULE_DIR);
    //if should_enable_overlay()?{
    //    _uninstall_module(id, defs::MODULE_UPDATE_TMP_DIR)?;
    //}else{
    //    return result;
    //}
    _uninstall_module(id, defs::MODULE_DIR)?;
    Ok(())
}

pub fn run_action(id: &str) -> Result<()> {
    let action_script_path = format!("/data/adb/modules/{}/action.sh", id);
    let _ = exec_script(&action_script_path, true);
    Ok(())
}

fn _enable_module(module_dir: &str, mid: &str, enable: bool) -> Result<()> {
    let src_module_path = format!("{module_dir}/{mid}");
    let src_module = Path::new(&src_module_path);
    ensure!(src_module.exists(), "module: {} not found!", mid);

    let disable_path = src_module.join(defs::DISABLE_FILE_NAME);
    if enable {
        if disable_path.exists() {
            std::fs::remove_file(&disable_path).with_context(|| {
                format!("Failed to remove disable file: {}", &disable_path.display())
            })?;
        }
    } else {
        ensure_file_exists(disable_path)?;
    }

    let _ = mark_module_state(mid, defs::DISABLE_FILE_NAME, !enable);

    Ok(())
}

pub fn enable_module(id: &str) -> Result<()> {
    let update_dir = Path::new(defs::MODULE_DIR);
    let update_dir_update = Path::new(defs::MODULE_UPDATE_TMP_DIR);

    //let result = enable_module_update(id, update_dir);
    //if should_enable_overlay()?{
    //    enable_module_update(id, update_dir_update)?;
    //}else{
    //    return result;
    //}
    enable_module_update(id, update_dir)?;
    Ok(())
}

pub fn enable_module_update(id: &str, update_dir: &Path) -> Result<()> {
    if let Some(module_dir_str) = update_dir.to_str() {
        _enable_module(module_dir_str, id, true)
    } else {
        log::info!("Enable module failed: Invalid path");
        Err(anyhow::anyhow!("Invalid module directory"))
    }
}

pub fn disable_module(id: &str) -> Result<()> {
    let update_dir = Path::new(defs::MODULE_DIR);
    let update_dir_update = Path::new(defs::MODULE_UPDATE_TMP_DIR);

    //let result = disable_module_update(id, update_dir);
    //if should_enable_overlay()?{
    //    disable_module_update(id, update_dir_update)?;
    //}else{
    //    return result;
    //}
    disable_module_update(id, update_dir)?;

    Ok(())
}

pub fn disable_module_update(id: &str, update_dir: &Path) -> Result<()> {
    if let Some(module_dir_str) = update_dir.to_str() {
        _enable_module(module_dir_str, id, false)
    } else {
        log::info!("Disable module failed: Invalid path");
        Err(anyhow::anyhow!("Invalid module directory"))
    }
}

pub fn disable_all_modules() -> Result<()> {
    // Skip disabling modules since boot completed
    if getprop("sys.boot_completed").as_deref() == Some("1") {
        info!("System boot completed, no need to disable all modules");
        return Ok(());
    }

    // we assume the module dir is already mounted
    //let _ = disable_all_modules_update(defs::MODULE_DIR);
    //disable_all_modules_update(defs::MODULE_UPDATE_TMP_DIR)?;
    disable_all_modules_update(defs::MODULE_DIR)?;
    Ok(())
}

pub fn disable_all_modules_update(dir: &str) -> Result<()> {
    let dir = std::fs::read_dir(dir)?;
    for entry in dir.flatten() {
        let path = entry.path();
        let disable_flag = path.join(defs::DISABLE_FILE_NAME);
        if let Err(e) = ensure_file_exists(disable_flag) {
            warn!("Failed to disable module: {}: {}", path.display(), e);
        }
    }
    Ok(())
}

fn _list_modules(path: &str) -> Vec<HashMap<String, String>> {
    // first check enabled modules
    let dir = std::fs::read_dir(path);
    let Ok(dir) = dir else {
        return Vec::new();
    };

    let mut modules: Vec<HashMap<String, String>> = Vec::new();

    for entry in dir.flatten() {
        let path = entry.path();
        info!("path: {}", path.display());
        let module_prop = path.join("module.prop");
        if !module_prop.exists() {
            continue;
        }
        let content = std::fs::read(&module_prop);
        let Ok(content) = content else {
            warn!("Failed to read file: {}", module_prop.display());
            continue;
        };
        let mut module_prop_map: HashMap<String, String> = HashMap::new();
        let encoding = encoding_rs::UTF_8;
        let result =
            PropertiesIter::new_with_encoding(Cursor::new(content), encoding).read_into(|k, v| {
                module_prop_map.insert(k, v);
            });

        if !module_prop_map.contains_key("id") || module_prop_map["id"].is_empty() {
            if let Some(id) = entry.file_name().to_str() {
                info!("Use dir name as module id: {}", id);
                module_prop_map.insert("id".to_owned(), id.to_owned());
            } else {
                info!("Failed to get module id: {:?}", module_prop);
                continue;
            }
        }

        // Add enabled, update, remove flags
        let enabled = !path.join(defs::DISABLE_FILE_NAME).exists();
        let update = path.join(defs::UPDATE_FILE_NAME).exists();
        let remove = path.join(defs::REMOVE_FILE_NAME).exists();
        let web = path.join(defs::MODULE_WEB_DIR).exists();
        let action = path.join(defs::MODULE_ACTION_SH).exists();

        module_prop_map.insert("enabled".to_owned(), enabled.to_string());
        module_prop_map.insert("update".to_owned(), update.to_string());
        module_prop_map.insert("remove".to_owned(), remove.to_string());
        module_prop_map.insert("web".to_owned(), web.to_string());
        module_prop_map.insert("action".to_owned(), action.to_string());

        if result.is_err() {
            warn!("Failed to parse module.prop: {}", module_prop.display());
            continue;
        }
        modules.push(module_prop_map);
    }

    modules
}

pub fn list_modules() -> Result<()> {
    let modules = _list_modules(defs::MODULE_DIR);
    println!("{}", serde_json::to_string_pretty(&modules)?);
    Ok(())
}

"""



