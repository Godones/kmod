use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from("target");
    let target = "x86_64-unknown-none";

    // 构建模块
    build_modules(&out_dir, &target);
}

fn build_modules(out_dir: &PathBuf, target: &str) {
    let modules = ["hello"];

    for module in modules.iter() {
        println!("Building module: {}", module);

        // 构建模块为静态库
        let status = Command::new("cargo")
            .current_dir(format!("modules/{}", module))
            .args(&[
                "build",
                "--release",
                "--target",
                target,
                "-Z",
                "build-std=core,alloc",
            ])
            .status()
            .expect("Failed to build module");

        if !status.success() {
            panic!("Failed to build module: {}", module);
        }

        // 处理生成的静态库，转换为可加载模块格式
        process_module_library(module, out_dir, target);
    }
}

fn process_module_library(module: &str, out_dir: &PathBuf, target: &str) {
    let lib_path = format!("./target/{}/release/lib{}.a", target, module);

    if !PathBuf::from(&lib_path).exists() {
        panic!("Library not found: {}", lib_path);
    }

    let lib_path = fs::canonicalize(lib_path)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // 创建模块临时目录
    let module_temp_dir = out_dir.join(module);
    fs::create_dir_all(&module_temp_dir).unwrap();

    // 从静态库提取目标文件
    let status = Command::new("ar")
        .args(&["x", &lib_path])
        .current_dir(&module_temp_dir)
        .status()
        .expect("Failed to extract from static library");

    if !status.success() {
        panic!("Failed to extract object files from {}", lib_path);
    }

    // 收集所有提取的.o文件
    let mut object_files = Vec::new();
    for entry in fs::read_dir(&module_temp_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "o") {
            object_files.push(path.clone());
            println!("Found object file: {:?}", path.file_name().unwrap());
        }
    }

    if object_files.is_empty() {
        panic!("No object files found in {}", lib_path);
    }

    // 将所有.o文件链接成内核模块
    create_kernel_module(module, out_dir, &object_files);
}

fn create_kernel_module(module: &str, out_dir: &PathBuf, object_files: &[PathBuf]) {
    let output_ko = out_dir.join(format!("{}.ko", module));

    // 构建ld命令参数
    let mut ld_args = Vec::new();
    ld_args.push("-r".to_string()); // 生成可重定位输出
    ld_args.push("-T".to_string());
    ld_args.push("linker.ld".to_string());
    ld_args.push("-o".to_string());
    ld_args.push(output_ko.to_str().unwrap().to_string());

    // 添加所有.o文件
    for obj_file in object_files {
        ld_args.push(obj_file.to_str().unwrap().to_string());
    }

    // 添加额外的链接器参数
    // ld_args.push("--gc-sections".to_string()); // 移除未使用的节区
    ld_args.push("--strip-debug".to_string());
    ld_args.push("--build-id=none".to_string()); // 禁用build ID以减少大小

    println!(
        "Linking kernel module with {} object files",
        object_files.len()
    );

    let status = Command::new("ld")
        .args(&ld_args)
        .status()
        .expect("Failed to link kernel module");

    if !status.success() {
        panic!("Failed to create kernel module for {}", module);
    }

    println!("Successfully created kernel module: {}.ko", module);

    // 验证生成的模块
    verify_kernel_module(&output_ko);
}

fn verify_kernel_module(ko_path: &PathBuf) {
    // 检查文件是否存在且非空
    let metadata = fs::metadata(ko_path).unwrap();
    if metadata.len() == 0 {
        panic!("Kernel module file is empty");
    }

    // 使用file命令检查文件类型
    let status = Command::new("file").arg(ko_path).status();

    if let Ok(status) = status {
        if status.success() {
            println!("Kernel module verification passed");
        }
    }

    // 使用readelf检查节区
    let status = Command::new("readelf")
        .args(&["-S", ko_path.to_str().unwrap()])
        .status();

    if let Ok(status) = status {
        if status.success() {
            println!("Kernel module sections are valid");
        }
    }
}
