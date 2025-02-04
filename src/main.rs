use std::{
    collections::{hash_map::DefaultHasher, BTreeMap, BTreeSet, HashMap},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    hash::Hasher,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context};
use cargo::{
    core::{package::MANIFEST_PREAMBLE, GitReference, Package, SourceId, Workspace},
    sources::path::PathSource,
    util::{CargoResult, Config},
};
use cargo_util::{paths, Sha256};
use clap::Parser;
use serde::Serialize;

/// Vendor all dependencies for a project locally
#[derive(Parser)]
#[command(name = "cargo-vendor", version)]
#[command(about = "Vendor all dependencies for a project locally")]
struct Options {
    /// Where to vendor crates (`vendor` by default)
    #[arg(default_value_t = String::from("vendor"))]
    path: String,
    /// Don't delete older crates in the vendor directory
    #[arg(long)]
    no_delete: bool,
    /// Sync one or more `Cargo.toml` or `Cargo.lock`
    #[arg(long, value_name = "TOML")]
    sync: Option<Vec<String>>,
    /// Always include version in subdir name
    #[arg(long)]
    versioned_dirs: bool,
    /// Use verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    /// No output printed to stdout
    #[arg(short, long)]
    quiet: bool,
    /// Coloring: auto, always, never
    #[arg(long, value_name = "WHEN")]
    color: Option<String>,
    /// Require Cargo.lock and cache are up to date
    #[arg(long)]
    frozen: bool,
    /// Require Cargo.lock is up to date
    #[arg(long)]
    locked: bool,
    /// Run without accessing the network
    #[arg(long)]
    offline: bool,
    /// Disallow two versions of one crate
    #[arg(long)]
    disallow_duplicates: bool,
    /// Only vendor git dependencies, not crates.io dependencies
    #[arg(long)]
    only_git_deps: bool,
    /// Vendor the main crate as well (additionally to its dependencies)
    #[arg(long)]
    vendor_main_crate: bool,
}

#[derive(Serialize)]
struct VendorConfig {
    source: BTreeMap<String, VendorSource>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase", untagged)]
enum VendorSource {
    Directory {
        directory: PathBuf,
    },
    Registry {
        registry: Option<String>,
        #[serde(rename = "replace-with")]
        replace_with: String,
    },
    Git {
        git: String,
        branch: Option<String>,
        tag: Option<String>,
        rev: Option<String>,
        #[serde(rename = "replace-with")]
        replace_with: String,
    },
}

const SOURCES_FILE_NAME: &str = ".sources";

fn main() {
    env_logger::init();

    // We're doing the vendoring operation outselves, so we don't actually want
    // to respect any of the `source` configuration in Cargo itself. That's
    // intended for other consumers of Cargo, but we want to go straight to the
    // source, e.g. crates.io, to fetch crates.
    let mut config = Config::default().unwrap();
    config.values_mut().unwrap().remove("source");

    let options = Options::parse();
    let result = real_main(options, &mut config);
    if let Err(e) = result {
        cargo::exit_with_error(e.into(), &mut *config.shell());
    }
}

fn real_main(options: Options, config: &mut Config) -> CargoResult<()> {
    config.configure(
        options.verbose.into(),
        options.quiet,
        options.color.as_deref(),
        options.frozen,
        options.locked,
        options.offline,
        &None, // target_dir,
        &[],   // unstable_flags,
        &[],   // cli_config,
    )?;

    let path = Path::new(&options.path);

    let sources_file = path.join(SOURCES_FILE_NAME);
    let is_multi_sources = sources_file.exists();
    if !is_multi_sources {
        fs::remove_dir_all(path).ok();
    }

    fs::create_dir_all(&path).with_context(|| format!("failed to create: `{}`", path.display()))?;

    if !is_multi_sources {
        let mut file = File::create(sources_file)?;
        file.write_all(serde_json::json!([]).to_string().as_bytes())?;
    }

    let workspaces = match options.sync {
        Some(list) => list
            .iter()
            .map(|path| {
                let path = Path::new(path);
                let manifest = if path.ends_with("Cargo.lock") {
                    config.cwd().join(path.with_file_name("Cargo.toml"))
                } else {
                    config.cwd().join(path)
                };
                Workspace::new(&manifest, config)
            })
            .collect::<CargoResult<Vec<_>>>()?,
        None => {
            let manifest = config.cwd().join("Cargo.toml");
            vec![Workspace::new(&manifest, config)?]
        }
    };

    let vendor_config = sync(
        &workspaces,
        &path,
        config,
        options.versioned_dirs,
        options.no_delete,
        options.disallow_duplicates,
        options.only_git_deps,
        options.vendor_main_crate,
    )
    .with_context(|| format!("failed to sync"))?;

    if !options.quiet {
        eprint!("To use vendored sources, add this to your .cargo/config for this project:\n\n");
        print!("{}", &toml::to_string(&vendor_config).unwrap());
    }

    Ok(())
}

fn sync(
    workspaces: &[Workspace],
    local_dst: &Path,
    config: &Config,
    explicit_version: bool,
    no_delete: bool,
    disallow_duplicates: bool,
    only_git_deps: bool,
    vendor_main_crate: bool,
) -> CargoResult<VendorConfig> {
    let canonical_local_dst = local_dst.canonicalize().unwrap_or(local_dst.to_path_buf());
    let mut ids = BTreeMap::new();
    let mut added_crates = Vec::new();

    // First up attempt to work around rust-lang/cargo#5956. Apparently build
    // artifacts sprout up in Cargo's global cache for whatever reason, although
    // it's unsure what tool is causing these issues at this time. For now we
    // apply a heavy-hammer approach which is to delete Cargo's unpacked version
    // of each crate to start off with. After we do this we'll re-resolve and
    // redownload again, which should trigger Cargo to re-extract all the
    // crates.
    //
    // Note that errors are largely ignored here as this is a best-effort
    // attempt. If anything fails here we basically just move on to the next
    // crate to work with.
    for ws in workspaces {
        let (packages, resolve) =
            cargo::ops::resolve_ws(&ws).with_context(|| "failed to load pkg lockfile")?;

        packages.get_many(resolve.iter())?;

        for pkg in resolve.iter() {
            // Don't delete actual source code!
            if pkg.source_id().is_path() {
                continue;
            }
            if pkg.source_id().is_git() {
                continue;
            }
            if let Ok(pkg) = packages.get_one(pkg) {
                drop(fs::remove_dir_all(pkg.manifest_path().parent().unwrap()));
            }
        }
    }

    let mut checksums = HashMap::new();

    for ws in workspaces {
        let main_pkg = ws.current().map(|x| x.name().as_str()).unwrap_or("");
        let (packages, resolve) =
            cargo::ops::resolve_ws(&ws).with_context(|| "failed to load pkg lockfile")?;

        packages.get_many(resolve.iter())?;

        for pkg in resolve.iter() {
            if pkg.source_id().is_path() {
                let path = pkg.source_id().url().to_file_path().expect("path");
                let canonical_path = path.canonicalize().unwrap_or(path.to_path_buf());
                if !(vendor_main_crate && main_pkg == pkg.name().as_str()) {
                    if canonical_path.starts_with(canonical_local_dst.as_path()) {
                        added_crates.push(canonical_path);
                    }
                    continue;
                }
            }
            ids.insert(
                pkg.clone(),
                packages
                    .get_one(pkg)
                    .with_context(|| "failed to fetch package")?
                    .clone(),
            );

            checksums.insert(pkg.clone(), resolve.checksums().get(&pkg).cloned());
        }
    }

    // https://github.com/rust-lang/cargo/blob/373c5d8ce43691f90929a74b047d7eababd04379/src/cargo/sources/registry/mod.rs#L248

    let mut versions = HashMap::new();
    for id in ids.keys() {
        let map = versions.entry(id.name()).or_insert_with(BTreeMap::default);
        map.insert(id.version(), id.source_id());
    }

    let sources_file = canonical_local_dst.join(SOURCES_FILE_NAME);
    let file = File::open(&sources_file)?;
    let source_paths = serde_json::from_reader::<_, BTreeSet<PathBuf>>(file)?
        .into_iter()
        .map(|p| canonical_local_dst.join(p))
        .collect::<Vec<_>>();

    let existing_crates: Vec<PathBuf> = source_paths
        .iter()
        .flat_map(|path| {
            path.read_dir()
                .map(|iter| {
                    iter.filter_map(|e| e.ok())
                        .filter(|e| e.path().join("Cargo.toml").exists())
                        .map(|e| e.path())
                        .collect::<Vec<_>>()
                })
                .unwrap_or(Vec::new())
        })
        .collect();

    let mut sources = BTreeSet::new();
    let mut tmp_buf = [0; 64 * 1024];
    for (id, pkg) in ids.iter() {
        // Next up, copy it to the vendor directory
        let src = pkg
            .manifest_path()
            .parent()
            .expect("manifest_path should point to a file");
        let max_version = *versions[&id.name()].iter().rev().next().unwrap().0;
        let dir_has_version_suffix = explicit_version || id.version() != max_version;
        let dst_name = if dir_has_version_suffix {
            if !explicit_version && disallow_duplicates {
                bail!(
                    "found duplicate versions of package `{}` at {} and {}, but this was \
                     disallowed via --disallow-duplicates",
                    pkg.name(),
                    id.version(),
                    max_version
                )
            }
            // Eg vendor/futures-0.1.13
            format!("{}-{}", id.name(), id.version())
        } else {
            // Eg vendor/futures
            id.name().to_string()
        };

        if !id.source_id().is_git() && only_git_deps {
            // Skip out if we only want to process git dependencies
            continue;
        }

        let source_dir = canonical_local_dst.join(source_id_to_dir_name(id.source_id()));
        if sources.insert(id.source_id()) {
            fs::create_dir_all(&source_dir)
                .with_context(|| format!("failed to create: `{}`", source_dir.display()))?;
        }
        let dst = source_dir.join(&dst_name);
        added_crates.push(dst.clone());

        let cksum = dst.join(".cargo-checksum.json");
        if dir_has_version_suffix && cksum.exists() {
            // Always re-copy directory without version suffix in case the version changed
            continue;
        }

        config.shell().status(
            "Vendoring",
            &format!("{} ({}) to {}", id, src.to_string_lossy(), dst.display()),
        )?;

        let _ = fs::remove_dir_all(&dst);
        let pathsource = PathSource::new(src, id.source_id(), config);
        let paths = pathsource.list_files(&pkg)?;
        let mut map = BTreeMap::new();
        cp_sources(&pkg, &src, &paths, &dst, &mut map, &mut tmp_buf)
            .with_context(|| format!("failed to copy over vendored sources for: {}", id))?;

        // Finally, emit the metadata about this package
        let json = serde_json::json!({
            "package": checksums.get(id),
            "files": map,
        });

        File::create(&cksum)?.write_all(json.to_string().as_bytes())?;
    }

    if !no_delete {
        for path in existing_crates {
            if !added_crates.contains(&path) {
                fs::remove_dir_all(&path)?;
            }
        }
    }

    let sources_file = canonical_local_dst.join(SOURCES_FILE_NAME);
    let file = File::open(&sources_file)?;
    let mut new_sources: BTreeSet<String> = sources
        .iter()
        .map(|src_id| source_id_to_dir_name(*src_id))
        .collect();
    let old_sources: BTreeSet<String> = serde_json::from_reader::<_, BTreeSet<String>>(file)?
        .difference(&new_sources)
        .map(|e| e.clone())
        .collect();
    for dir_name in old_sources {
        let path = canonical_local_dst.join(dir_name.clone());
        if path.is_dir() {
            if path.read_dir()?.next().is_none() {
                fs::remove_dir(path)?;
            } else {
                new_sources.insert(dir_name.clone());
            }
        }
    }
    let file = File::create(sources_file)?;
    serde_json::to_writer(file, &new_sources)?;

    // add our vendored source
    let dir = local_dst.to_path_buf();
    let mut config = BTreeMap::new();

    // replace original sources with vendor
    for source_id in sources {
        let name = if source_id.is_registry() {
            source_id.display_registry_name()
        } else {
            source_id.url().to_string()
        };

        let replace_name = format!("vendor+{}", name);

        let src_id_string = source_id_to_dir_name(source_id);
        let src_dir = dir.join(src_id_string.clone());
        config.insert(
            replace_name.clone(),
            VendorSource::Directory { directory: src_dir },
        );

        // if source id is a path and vendor_main_crate, skip the source replacement
        if source_id.is_path() && vendor_main_crate {
            continue;
        }

        let source = if source_id.is_registry() {
            if source_id.is_crates_io() {
                VendorSource::Registry {
                    registry: None,
                    replace_with: replace_name,
                }
            } else {
                VendorSource::Registry {
                    registry: Some(source_id.url().to_string()),
                    replace_with: replace_name,
                }
            }
        } else if source_id.is_git() {
            let mut branch = None;
            let mut tag = None;
            let mut rev = None;
            if let Some(reference) = source_id.git_reference() {
                match *reference {
                    GitReference::Branch(ref b) => branch = Some(b.clone()),
                    GitReference::Tag(ref t) => tag = Some(t.clone()),
                    GitReference::Rev(ref r) => rev = Some(r.clone()),
                    GitReference::DefaultBranch => {}
                }
            }
            VendorSource::Git {
                git: source_id.url().to_string(),
                branch,
                tag,
                rev,
                replace_with: replace_name,
            }
        } else {
            panic!("Invalid source ID: {}", source_id)
        };
        config.insert(name, source);
    }

    Ok(VendorConfig { source: config })
}

fn cp_sources(
    pkg: &Package,
    src: &Path,
    paths: &Vec<PathBuf>,
    dst: &Path,
    cksums: &mut BTreeMap<String, String>,
    tmp_buf: &mut [u8],
) -> CargoResult<()> {
    for p in paths {
        let relative = p.strip_prefix(&src).unwrap();

        match relative.file_name().map(OsStr::to_str).flatten() {
            // Skip git config files as they're not relevant to builds most of
            // the time and if we respect them (e.g.  in git) then it'll
            // probably mess with the checksums when a vendor dir is checked
            // into someone else's source control
            Some(".gitattributes") | Some(".gitignore") | Some(".git") => continue,

            // Temporary Cargo files
            Some(".cargo-ok") => continue,

            // Skip patch-style orig/rej files. Published crates on crates.io
            // have `Cargo.toml.orig` which we don't want to use here and
            // otherwise these are rarely used as part of the build process.
            Some(filename) => {
                if filename.ends_with(".orig") || filename.ends_with(".rej") {
                    continue;
                }
            }
            _ => (),
        };

        // Join pathname components individually to make sure that the joined
        // path uses the correct directory separators everywhere, since
        // `relative` may use Unix-style and `dst` may require Windows-style
        // backslashes.
        let dst = relative
            .iter()
            .fold(dst.to_owned(), |acc, component| acc.join(&component));

        paths::create_dir_all(dst.parent().unwrap())?;
        let mut dst_opts = OpenOptions::new();
        dst_opts.write(true).create(true).truncate(true);
        // When vendoring git dependencies, the manifest has not been normalized like it would be
        // when published. This causes issue when the manifest is using workspace inheritance.
        // To get around this issue we use the "original" manifest after `{}.workspace = true`
        // has been resolved for git dependencies.
        let cksum = if dst.file_name() == Some(OsStr::new("Cargo.toml"))
            && pkg.package_id().source_id().is_git()
        {
            let original_toml = toml::to_string_pretty(pkg.manifest().original())?;
            let contents = format!("{}\n{}", MANIFEST_PREAMBLE, original_toml);
            copy_and_checksum(
                &dst,
                &mut dst_opts,
                &mut contents.as_bytes(),
                "Generated Cargo.toml",
                tmp_buf,
            )?
        } else {
            let mut src = File::open(&p).with_context(|| format!("failed to open {:?}", &p))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
                let src_metadata = src
                    .metadata()
                    .with_context(|| format!("failed to stat {:?}", p))?;
                dst_opts.mode(src_metadata.mode());
            }
            copy_and_checksum(
                &dst,
                &mut dst_opts,
                &mut src,
                &p.display().to_string(),
                tmp_buf,
            )?
        };

        cksums.insert(relative.to_str().unwrap().replace("\\", "/"), cksum);
    }

    Ok(())
}

fn copy_and_checksum<T: Read>(
    dst_path: &Path,
    dst_opts: &mut OpenOptions,
    contents: &mut T,
    contents_path: &str,
    buf: &mut [u8],
) -> CargoResult<String> {
    let mut dst = dst_opts
        .open(dst_path)
        .with_context(|| format!("failed to create {:?}", dst_path))?;
    // Not going to bother setting mode on pre-existing files, since there
    // shouldn't be any under normal conditions.
    let mut cksum = Sha256::new();
    loop {
        let n = contents
            .read(buf)
            .with_context(|| format!("failed to read from {:?}", contents_path))?;
        if n == 0 {
            break Ok(cksum.finish_hex());
        }
        let data = &buf[..n];
        cksum.update(data);
        dst.write_all(data)
            .with_context(|| format!("failed to write to {:?}", dst_path))?;
    }
}

fn source_id_to_dir_name(src_id: SourceId) -> String {
    let src_type = if src_id.is_registry() {
        "registry"
    } else if src_id.is_git() {
        "git"
    } else {
        panic!()
    };
    let mut hasher = DefaultHasher::new();
    src_id.stable_hash(Path::new(""), &mut hasher);
    let src_hash = hasher.finish();
    let mut bytes = [0; 8];
    for i in 0..7 {
        bytes[i] = (src_hash >> i * 8) as u8
    }
    format!("{}-{}", src_type, hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        s.push(hex((byte >> 4) & 0xf));
        s.push(hex((byte >> 0) & 0xf));
    }

    return s;

    fn hex(b: u8) -> char {
        if b < 10 {
            (b'0' + b) as char
        } else {
            (b'a' + b - 10) as char
        }
    }
}
