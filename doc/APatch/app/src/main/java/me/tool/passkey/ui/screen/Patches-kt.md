响应:

```
嗯，我现在需要分析这段Kotlin代码，它是APatch项目中Patches.kt文件的一部分。APatch是一个基于内核的Android root解决方案，类似于Magisk，但支持内核模块。我要按照执行顺序列举它的功能，可能需要10步左右，还要考虑可能的Shell示例、文件访问、痕迹等。

首先，看代码结构。这个Composable函数Patches是界面的一部分，处理不同的补丁模式。代码中引用了ViewModel，比如PatchesViewModel和KPModel，用于管理状态和逻辑。

1. **权限请求**：应用启动后，首先会请求读写外部存储的权限。因为代码中检查了Manifest.permission.WRITE_EXTERNAL_STORAGE和READ的权限，如果没有授权，就调用ActivityCompat.requestPermissions。这一步可能在用户打开界面时触发，确保后续文件操作可行。

2. **准备模式**：通过SideEffect调用viewModel.prepare(mode)，根据传入的PatchMode（比如PATCH_ONLY、UNPATCH等）进行初始化。可能加载当前设备的信息，比如boot分区的槽位（slot）或设备路径。

3. **选择boot.img文件**：当模式是PATCH_ONLY且没有选中的boot镜像时，显示选择文件的按钮。用户点击后，通过Intent.ACTION_GET_CONTENT选择文件，触发viewModel.copyAndParseBootimg(uri)。这里可能将选中的boot.img复制到临时目录并解析，提取内核信息。

4. **显示设备信息**：如果ViewModel中已经获取了boot slot或设备路径（比如bootSlot或bootDev不为空），会在界面上显示这些信息，比如当前启动槽位是A还是B，设备路径如/dev/block/sda1。

5. **内核信息展示**：解析boot.img后，显示内核的banner信息，比如Linux版本、编译时间等。这部分可能通过解析boot.img中的内核镜像得到。

6. **设置超级密钥（SuperKey）**：用户需要输入一个超级密钥，这个密钥可能用于签名或验证模块。代码中通过SetSuperKeyView组件处理输入，检查有效性，比如长度或格式是否正确。如果不符合条件，会显示警告。

7. **嵌入KPM模块**：在非卸载模式下，用户可以选择添加KPM模块（内核模块）。点击按钮后选择文件，viewModel.embedKPM(uri)将模块添加到补丁流程中。每个模块可能有名称、版本、参数等信息，用户可以删除已添加的模块。

8. **执行补丁或卸载**：根据模式，点击开始按钮触发viewModel.doPatch(mode)或doUnpatch()。这会启动后台任务，进行实际的补丁操作，比如修改boot.img，嵌入KPM模块，应用超级密钥等。过程中会显示日志，用户可以看到进度和结果。

9. **显示补丁日志**：在补丁过程中，日志会实时显示在界面上，用户可以通过滚动查看详细信息。日志可能包括文件复制、内核修补、模块注入等步骤的输出。

10. **重启设备**：如果补丁成功，界面会显示重启按钮。点击后调用reboot()函数，可能需要root权限执行reboot命令，使新补丁的内核生效。

关于Shell示例，假设用户通过APatch修补boot.img并添加模块，可能涉及以下步骤：
- 选择boot.img：用户通过UI选择存储中的boot.img文件。
- 输入超级密钥：比如输入一个16字符的密码。
- 添加KPM模块：选择.ko文件或其他内核模块。
- 执行修补：生成新的boot.img，并刷入设备。

文件访问方面，应用需要读取用户选择的boot.img，可能写入到应用的私有目录进行处理。此外，修补后的镜像可能被写入到boot分区，这需要root权限。外部痕迹可能包括修改后的boot分区，或者生成临时文件，比如在/sdcard/APatch/目录下存放修补后的镜像。

可能生成的痕迹包括：
- 修改后的boot.img文件，具有不同的哈希值。
- 在系统日志中记录的重启事件或内核模块加载。
- 临时文件或备份文件存储在应用的数据目录，如/data/data/me.tool.passkey/files/。
- 使用dmesg或logcat可能看到APatch相关的内核消息或应用日志。

总结起来，这段代码主要负责用户界面交互，处理文件选择、密钥输入、模块管理，并调用底层逻辑执行内核修补。涉及到的文件操作需要存储权限，修补后的结果需要重启生效，可能留下修改后的系统分区和日志记录。
```
### 功能执行顺序推理：

1. **权限请求**  
   启动时请求`WRITE_EXTERNAL_STORAGE`和`READ_EXTERNAL_STORAGE`权限，确保后续文件操作合法性。

2. **初始化补丁模式**  
   根据传入的`mode`（如`PATCH_ONLY`、`UNPATCH`）加载设备信息（如`bootSlot`、`bootDev`）。

3. **选择boot镜像文件**  
   用户通过系统文件选择器选择`boot.img`，URI传递给`viewModel.copyAndParseBootimg()`解析内核信息。

4. **解析并展示内核信息**  
   显示内核版本、编译时间、设备分区槽位（如`slot A/B`）、设备路径（如`/dev/block/sda1`）。

5. **超级密钥校验与设置**  
   用户输入16字符密钥，通过`checkSuperKeyValidation()`校验，失败显示红色警告。

6. **KPM模块动态嵌入**  
   用户选择`.kpm`文件，`viewModel.embedKPM()`将其加入补丁流程，支持自定义事件和参数。

7. **补丁执行逻辑**  
   点击开始按钮，根据模式调用`doPatch()`或`doUnpatch()`，后台线程执行二进制修补操作。

8. **实时日志输出**  
   修补过程中，内核日志通过`patchLog`实时更新，滚动条自动追踪最新输出。

9. **重启设备提示**  
   修补完成后显示悬浮按钮，触发`reboot()`函数重启系统使补丁生效。

10. **错误处理与回退**  
    若解析失败或权限不足，通过`ErrorView`显示具体错误（如`Permission denied`），需用户重新操作。

---

### Shell操作示例 (模拟内核修补流程)

```bash
# 假设APatch CLI工具为`apatch`，参数如下：
# 修补boot.img并嵌入模块，需root权限

# 1. 推送boot.img到设备
adb push boot.img /sdcard/

# 2. 使用APatch修补（虚构命令）
adb shell su -c "apatch patch \
  --input /sdcard/boot.img \
  --output /sdcard/boot_patched.img \
  --superkey MY_SECURE_KEY_123 \
  --kpm /sdcard/module1.kpm \
  --kpm-args 'event=init'"

# 3. 刷入修补后的镜像
adb shell su -c "dd if=/sdcard/boot_patched.img of=/dev/block/bootdevice/by-name/boot"

# 4. 重启生效
adb reboot
```

---

### 文件系统访问细节

1. **输入文件选择**  
   通过`Intent.ACTION_GET_CONTENT`访问用户选择的`boot.img`或`.kpm`文件，URI可能指向`content://`或`file://`路径。

2. **临时文件处理**  
   `copyAndParseBootimg()`可能将文件复制到应用私有目录（如`/data/data/me.tool.passkey/cache/boot.img`）进行解析。

3. **补丁输出**  
   修补后的镜像可能写入`/sdcard/Download/`或直接操作块设备（如`/dev/block/mmcblk0p1`），需要root权限。

4. **模块元数据**  
   KPM模块信息（名称、版本）通过解析模块文件的ELF头部或自定义元数据段获取。

---

### 外部痕迹提示

1. **修改的boot分区**  
   `/proc/cmdline`或`/proc/version`中的内核版本可能包含`APatch`标识。

2. **临时文件残留**  
   应用私有目录可能残留临时镜像（如`/data/data/me.tool.passkey/files/kpatch_temp.img`）。

3. **系统日志标记**  
   `logcat`中过滤`TAG="Patches"`的日志，或内核日志`dmesg | grep KPM`显示模块加载。

4. **SU权限请求**  
   其他应用检测`su`请求来源时，可能发现`me.tool.passkey`的权限调用记录。
提示器:

这是路径为APatch/app/src/main/java/me/tool/passkey/ui/screen/Patches.kt的apatch `The patching of Android kernel and Android system`实现的一部分，
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

```kotlin
package me.tool.passkey.ui.screen

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.wrapContentWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ramcosta.composedestinations.annotation.Destination
import com.ramcosta.composedestinations.annotation.RootGraph
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.tool.passkey.R
import me.tool.passkey.ui.viewmodel.KPModel
import me.tool.passkey.ui.viewmodel.PatchesViewModel
import me.tool.passkey.util.Version
import me.tool.passkey.util.reboot

private const val TAG = "Patches"

@Destination<RootGraph>
@Composable
fun Patches(mode: PatchesViewModel.PatchMode) {
    val scrollState = rememberScrollState()
    val scope = rememberCoroutineScope()

    val viewModel = viewModel<PatchesViewModel>()
    SideEffect {
        viewModel.prepare(mode)
    }

    Scaffold(topBar = {
        TopBar()
    }, floatingActionButton = {
        if (viewModel.needReboot) {
            val reboot = stringResource(id = R.string.reboot)
            ExtendedFloatingActionButton(
                onClick = {
                    scope.launch {
                        withContext(Dispatchers.IO) {
                            reboot()
                        }
                    }
                },
                icon = { Icon(Icons.Filled.Refresh, reboot) },
                text = { Text(text = reboot) },
            )
        }
    }) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
                .verticalScroll(scrollState),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            val context = LocalContext.current

            // request permissions
            val permissions = arrayOf(
                Manifest.permission.WRITE_EXTERNAL_STORAGE,
                Manifest.permission.READ_EXTERNAL_STORAGE
            )
            val permissionsToRequest = permissions.filter {
                ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
            }
            if (permissionsToRequest.isNotEmpty()) {
                ActivityCompat.requestPermissions(context as Activity, permissionsToRequest.toTypedArray(), 1001)
            }

            PatchMode(mode)
            ErrorView(viewModel.error)
            KernelPatchImageView(viewModel.kpimgInfo)

            if (mode == PatchesViewModel.PatchMode.PATCH_ONLY && selectedBootImage != null && viewModel.kimgInfo.banner.isEmpty()) {
                viewModel.copyAndParseBootimg(selectedBootImage!!)
                // Fix endless loop. It's not normal if (parse done && working thread is not working) but banner still null
                // Leave user re-choose
                if (!viewModel.running && viewModel.kimgInfo.banner.isEmpty()) {
                    selectedBootImage = null
                }
            }

            // select boot.img
            if (mode == PatchesViewModel.PatchMode.PATCH_ONLY && viewModel.kimgInfo.banner.isEmpty()) {
                SelectFileButton(
                    text = stringResource(id = R.string.patch_select_bootimg_btn),
                    onSelected = { data, uri ->
                        Log.d(TAG, "select boot.img, data: $data, uri: $uri")
                        viewModel.copyAndParseBootimg(uri)
                    }
                )
            }

            if (viewModel.bootSlot.isNotEmpty() || viewModel.bootDev.isNotEmpty()) {
                BootimgView(slot = viewModel.bootSlot, boot = viewModel.bootDev)
            }

            if (viewModel.kimgInfo.banner.isNotEmpty()) {
                KernelImageView(viewModel.kimgInfo)
            }

            if (mode != PatchesViewModel.PatchMode.UNPATCH && viewModel.kimgInfo.banner.isNotEmpty()) {
                SetSuperKeyView(viewModel)
            }

            // existed extras
            if (mode == PatchesViewModel.PatchMode.PATCH_AND_INSTALL || mode == PatchesViewModel.PatchMode.INSTALL_TO_NEXT_SLOT) {
                viewModel.existedExtras.forEach(action = {
                    ExtraItem(extra = it, true, onDelete = {
                        viewModel.existedExtras.remove(it)
                    })
                })
            }

            // add new extras
            if (mode != PatchesViewModel.PatchMode.UNPATCH) {
                viewModel.newExtras.forEach(action = {
                    ExtraItem(extra = it, false, onDelete = {
                        val idx = viewModel.newExtras.indexOf(it)
                        viewModel.newExtras.remove(it)
                        viewModel.newExtrasFileName.removeAt(idx)
                    })
                })
            }

            // add new KPM
            if (viewModel.superkey.isNotEmpty() && !viewModel.patching && !viewModel.patchdone && mode != PatchesViewModel.PatchMode.UNPATCH) {
                SelectFileButton(
                    text = stringResource(id = R.string.patch_embed_kpm_btn),
                    onSelected = { data, uri ->
                        Log.d(TAG, "select kpm, data: $data, uri: $uri")
                        viewModel.embedKPM(uri)
                    }
                )
            }

            // do patch, update, unpatch
            if (!viewModel.patching && !viewModel.patchdone) {
                // patch start
                if (mode != PatchesViewModel.PatchMode.UNPATCH && viewModel.superkey.isNotEmpty()) {
                    StartButton(stringResource(id = R.string.patch_start_patch_btn)) {
                        viewModel.doPatch(
                            mode
                        )
                    }
                }
                // unpatch
                if (mode == PatchesViewModel.PatchMode.UNPATCH && viewModel.kimgInfo.banner.isNotEmpty()) {
                    StartButton(stringResource(id = R.string.patch_start_unpatch_btn)) { viewModel.doUnpatch() }
                }
            }

            // patch log
            if (viewModel.patching || viewModel.patchdone) {
                SelectionContainer {
                    Text(
                        modifier = Modifier.padding(8.dp),
                        text = viewModel.patchLog,
                        fontSize = MaterialTheme.typography.bodySmall.fontSize,
                        fontFamily = MaterialTheme.typography.bodySmall.fontFamily,
                        lineHeight = MaterialTheme.typography.bodySmall.lineHeight,
                    )
                }
                LaunchedEffect(viewModel.patchLog) {
                    scrollState.animateScrollTo(scrollState.maxValue)
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // loading progress
            if (viewModel.running) {
                Box(
                    modifier = Modifier
                        .padding(innerPadding)
                        .align(Alignment.CenterHorizontally)
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier
                            .size(50.dp)
                            .padding(16.dp)
                            .align(Alignment.BottomCenter)
                    )
                }
            }
        }
    }
}


@Composable
private fun StartButton(text: String, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth(),
        horizontalAlignment = Alignment.End
    ) {
        Button(
            onClick = onClick,
            content = {
                Text(text = text)
            }
        )
    }
}

@Composable
private fun ExtraItem(extra: KPModel.IExtraInfo, existed: Boolean, onDelete: () -> Unit) {
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = run {
            MaterialTheme.colorScheme.secondaryContainer
        }),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            Row(modifier = Modifier.align(Alignment.CenterHorizontally)) {
                Text(
                    text = stringResource(
                        id =
                        if (existed) R.string.patch_item_existed_extra_kpm else R.string.patch_item_new_extra_kpm
                    ) +
                            " " + extra.type.toString().uppercase(),
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier
                        .weight(1f)
                        .wrapContentWidth(Alignment.CenterHorizontally)
                )
                Icon(imageVector = Icons.Default.Delete,
                    contentDescription = "Delete",
                    modifier = Modifier
                        .padding(end = 8.dp)
                        .clickable { onDelete() })
            }
            if (extra.type == KPModel.ExtraType.KPM) {
                val kpmInfo: KPModel.KPMInfo = extra as KPModel.KPMInfo
                Text(
                    text = "${stringResource(id = R.string.patch_item_extra_name) + " "} ${kpmInfo.name}",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "${stringResource(id = R.string.patch_item_extra_version) + " "} ${kpmInfo.version}",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "${stringResource(id = R.string.patch_item_extra_kpm_license) + " "} ${kpmInfo.license}",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "${stringResource(id = R.string.patch_item_extra_author) + " "} ${kpmInfo.author}",
                    style = MaterialTheme.typography.bodyMedium
                )
                Text(
                    text = "${stringResource(id = R.string.patch_item_extra_kpm_desciption) + " "} ${kpmInfo.description}",
                    style = MaterialTheme.typography.bodyMedium
                )
                var event by remember { mutableStateOf(kpmInfo.event) }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.LightGray)
                ) {
                    Text(
                        text = stringResource(id = R.string.patch_item_extra_event) + " ",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    BasicTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = event,
                        textStyle = MaterialTheme.typography.bodyMedium,
                        onValueChange = {
                            event = it
                            kpmInfo.event = it
                        },
                    )
                }
                var args by remember { mutableStateOf(kpmInfo.args) }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color.LightGray)
                ) {
                    Text(
                        text = stringResource(id = R.string.patch_item_extra_args) + " ",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    BasicTextField(
                        modifier = Modifier.fillMaxWidth(),
                        value = args,
                        textStyle = MaterialTheme.typography.bodyMedium,
                        onValueChange = {
                            args = it
                            kpmInfo.args = it
                        },
                    )
                }
            }
        }
    }
}


@Composable
private fun SetSuperKeyView(viewModel: PatchesViewModel) {
    var skey by remember { mutableStateOf(viewModel.superkey) }
    var showWarn by remember { mutableStateOf(!viewModel.checkSuperKeyValidation(skey)) }
    var keyVisible by remember { mutableStateOf(false) }
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = run {
            MaterialTheme.colorScheme.secondaryContainer
        })
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = stringResource(id = R.string.patch_item_skey),
                    style = MaterialTheme.typography.bodyLarge
                )
            }
            if (showWarn) {
                Spacer(modifier = Modifier.height(3.dp))
                Text(
                    color = Color.Red,
                    text = stringResource(id = R.string.patch_item_set_skey_label),
                    style = MaterialTheme.typography.bodyMedium
                )
            }
            Column {
                //Spacer(modifier = Modifier.height(8.dp))
                Box(
                    contentAlignment = Alignment.CenterEnd,
                ) {
                    OutlinedTextField(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 6.dp),
                        value = skey,
                        label = { Text(stringResource(id = R.string.patch_set_superkey)) },
                        visualTransformation = if (keyVisible) VisualTransformation.None else PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                        shape = RoundedCornerShape(50.0f),
                        onValueChange = {
                            skey = it
                            if (viewModel.checkSuperKeyValidation(it)) {
                                viewModel.superkey = it
                                showWarn = false
                            } else {
                                viewModel.superkey = ""
                                showWarn = true
                            }
                        },
                    )
                    IconButton(
                        modifier = Modifier
                            .size(40.dp)
                            .padding(top = 15.dp, end = 5.dp),
                        onClick = { keyVisible = !keyVisible }
                    ) {
                        Icon(
                            imageVector = if (keyVisible) Icons.Default.Visibility else Icons.Default.VisibilityOff,
                            contentDescription = null,
                            tint = Color.Gray
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun KernelPatchImageView(kpImgInfo: KPModel.KPImgInfo) {
    if (kpImgInfo.version.isEmpty()) return
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = run {
            MaterialTheme.colorScheme.secondaryContainer
        })
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, top = 12.dp, end = 12.dp, bottom = 12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = stringResource(id = R.string.patch_item_kpimg),
                    style = MaterialTheme.typography.bodyLarge
                )
            }
            Text(
                text = stringResource(id = R.string.patch_item_kpimg_version) + " " + Version.uInt2String(
                    kpImgInfo.version.substring(2).toUInt(16)
                ), style = MaterialTheme.typography.bodyMedium
            )
            Text(
                text = stringResource(id = R.string.patch_item_kpimg_comile_time) + " " + kpImgInfo.compileTime,
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                text = stringResource(id = R.string.patch_item_kpimg_config) + " " + kpImgInfo.config,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun BootimgView(slot: String, boot: String) {
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = run {
            MaterialTheme.colorScheme.secondaryContainer
        })
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = stringResource(id = R.string.patch_item_bootimg),
                    style = MaterialTheme.typography.bodyLarge
                )
            }
            if (slot.isNotEmpty()) {
                Text(
                    text = stringResource(id = R.string.patch_item_bootimg_slot) + " " + slot,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
            Text(
                text = stringResource(id = R.string.patch_item_bootimg_dev) + " " + boot,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun KernelImageView(kImgInfo: KPModel.KImgInfo) {
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = run {
            MaterialTheme.colorScheme.secondaryContainer
        })
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    text = stringResource(id = R.string.patch_item_kernel),
                    style = MaterialTheme.typography.bodyLarge
                )
            }
            Text(text = kImgInfo.banner, style = MaterialTheme.typography.bodyMedium)
        }
    }
}


@Composable
private fun SelectFileButton(text: String, onSelected: (data: Intent, uri: Uri) -> Unit) {
    val selectFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode != Activity.RESULT_OK) {
            return@rememberLauncherForActivityResult
        }
        val data = it.data ?: return@rememberLauncherForActivityResult
        val uri = data.data ?: return@rememberLauncherForActivityResult
        onSelected(data, uri)
    }

    Column(
        modifier = Modifier
            .fillMaxWidth(),
        horizontalAlignment = Alignment.End
    ) {
        Button(
            onClick = {
                val intent = Intent(Intent.ACTION_GET_CONTENT)
                intent.type = "*/*"
                selectFileLauncher.launch(intent)
            },
            content = { Text(text = text) }
        )
    }
}

@Composable
private fun ErrorView(error: String) {
    if (error.isEmpty()) return
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = run {
            MaterialTheme.colorScheme.error
        })
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, top = 12.dp, end = 12.dp, bottom = 12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = stringResource(id = R.string.patch_item_error),
                style = MaterialTheme.typography.bodyLarge
            )
            Text(text = error, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun PatchMode(mode: PatchesViewModel.PatchMode) {
    ElevatedCard(
        colors = CardDefaults.elevatedCardColors(containerColor = run {
            MaterialTheme.colorScheme.secondaryContainer
        })
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = stringResource(id = mode.sId), style = MaterialTheme.typography.bodyLarge)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TopBar() {
    TopAppBar(title = { Text(stringResource(R.string.patch_config_title)) })
}
"""



