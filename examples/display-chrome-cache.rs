use chrono::{DateTime, Local, NaiveDate, TimeZone};
use clap::{CommandFactory, Parser};
use std::{fmt::Debug, fs, path::PathBuf, time::SystemTime};

use chrome_cache_parser::{
    is_block_file_cache, is_simple_cache, CCPError, CCPResult, ChromeCache, SimpleCache,
    SimpleCacheEntry,
};

/// A simple command line tool to display the contents of a Chrome cache directory.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the cache directory (containing an index file)
    #[arg(short, long)]
    path: Option<String>,

    /// Whether to be silent
    #[arg(short, long)]
    silent: bool,

    /// Filter entries cached on or after this date (format: YYYY-MM-DD)
    #[arg(long)]
    since: Option<String>,

    /// Filter entries with body size >= this value (e.g., 10kb, 1mb, 500b)
    #[arg(long)]
    min_size: Option<String>,

    /// Extract matching entries to this directory
    #[arg(short, long)]
    extract: Option<String>,
}

fn default_cache_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let windows_path = home.join("AppData/Local/Google/Chrome/User Data/Default/Cache/Cache_Data");
    let linux_path = home.join(".cache/google-chrome/Default/Cache");
    let mac_path = home.join("Library/Caches/Google/Chrome/Default/Cache/Cache_Data");

    if windows_path.exists() {
        Some(windows_path)
    } else if linux_path.exists() {
        Some(linux_path)
    } else if mac_path.exists() {
        Some(mac_path)
    } else {
        None
    }
}

fn parse_size_filter(size_str: &str) -> CCPResult<usize> {
    let size_str = size_str.trim().to_lowercase();

    let (num_str, multiplier) = if size_str.ends_with("kb") {
        (&size_str[..size_str.len() - 2], 1024)
    } else if size_str.ends_with("mb") {
        (&size_str[..size_str.len() - 2], 1024 * 1024)
    } else if size_str.ends_with("gb") {
        (&size_str[..size_str.len() - 2], 1024 * 1024 * 1024)
    } else if size_str.ends_with("b") {
        (&size_str[..size_str.len() - 1], 1)
    } else {
        // Assume bytes if no suffix
        (size_str.as_str(), 1)
    };

    let num: usize = num_str
        .trim()
        .parse()
        .map_err(|e| CCPError::InvalidData(format!("Invalid size '{}': {}", size_str, e)))?;

    Ok(num * multiplier)
}

fn parse_date_filter(date_str: &str) -> CCPResult<SystemTime> {
    let naive_date = NaiveDate::parse_from_str(date_str, "%Y-%m-%d")
        .map_err(|e| CCPError::InvalidData(format!("Invalid date format '{}': {}", date_str, e)))?;

    let local_datetime = Local
        .from_local_datetime(&naive_date.and_hms_opt(0, 0, 0).unwrap())
        .single()
        .ok_or_else(|| CCPError::InvalidData("Ambiguous date".to_string()))?;

    Ok(SystemTime::from(local_datetime))
}

/// Extract file extension from URL
fn get_extension_from_url(url: &str) -> Option<String> {
    // Remove query string and fragment
    let path = url.split('?').next()?.split('#').next()?;

    // Get the last path component
    let filename = path.rsplit('/').next()?;

    // Find the extension
    if let Some(dot_pos) = filename.rfind('.') {
        let ext = &filename[dot_pos + 1..];
        // Validate it looks like a real extension (1-10 chars, alphanumeric)
        if !ext.is_empty() && ext.len() <= 10 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Some(ext.to_lowercase());
        }
    }

    None
}

/// Get a safe filename from URL and hash
fn get_safe_filename(entry: &SimpleCacheEntry) -> String {
    let ext = get_extension_from_url(&entry.key).unwrap_or_else(|| "bin".to_string());

    // Use hash as the base filename to ensure uniqueness
    format!("{:016x}.{}", entry.hash, ext)
}

/// Binary file signatures and their extensions (binary formats first!)
const SIGNATURES: &[(&[u8], &str)] = &[
    (b"\x89PNG\r\n\x1a\n", "png"), // PNG (8 bytes)
    (b"\x89PNG", "png"),           // PNG (4 bytes fallback)
    (b"\xff\xd8\xff", "jpg"),      // JPEG
    (b"GIF87a", "gif"),            // GIF87
    (b"GIF89a", "gif"),            // GIF89
    (b"RIFF", "webp"),             // WebP (RIFF container)
    (b"PK\x03\x04", "zip"),        // ZIP
    (b"\x1f\x8b", "gz"),           // Gzip
    (b"BM", "bmp"),                // BMP
    (b"ID3", "mp3"),               // MP3 with ID3
    (b"OggS", "ogg"),              // OGG
    (b"<svg", "svg"),              // SVG
];

/// Find binary content in cache data and return (content, detected_extension)
fn extract_content_with_type(data: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    // Search for binary signatures starting from offset 100 to skip cache metadata/headers
    let search_start = 100.min(data.len());

    for (sig, ext) in SIGNATURES {
        if let Some(pos) = data[search_start..]
            .windows(sig.len())
            .position(|w| w == *sig)
        {
            let actual_pos = search_start + pos;
            return Some((data[actual_pos..].to_vec(), ext));
        }
    }

    // Check for MP4 (ftyp at offset 4 from content start)
    for i in search_start..data.len().saturating_sub(12) {
        if data.get(i + 4..i + 8) == Some(b"ftyp") {
            return Some((data[i..].to_vec(), "mp4"));
        }
    }

    // Fallback: couldn't find a known signature
    None
}

/// Extract entry to a file
fn extract_entry(entry: &SimpleCacheEntry, output_dir: &PathBuf) -> CCPResult<PathBuf> {
    // Read the cache file and extract the actual content
    let cache_data = fs::read(&entry.file_path)?;

    // Try to extract content and detect its actual type
    if let Some((content, detected_ext)) = extract_content_with_type(&cache_data) {
        // Use the detected extension instead of URL extension
        let filename = format!("{:016x}.{}", entry.hash, detected_ext);
        let output_path = output_dir.join(&filename);
        fs::write(&output_path, content)?;
        return Ok(output_path);
    }

    // Fallback: use URL extension and copy body_data
    let filename = get_safe_filename(entry);
    let output_path = output_dir.join(&filename);

    if !entry.body_data.is_empty() {
        fs::write(&output_path, &entry.body_data)?;
    } else {
        // Last resort: copy the whole file
        fs::copy(&entry.file_path, &output_path)?;
    }

    Ok(output_path)
}

fn main() {
    let args = Args::parse();
    if let Err(e) = display_cache(args) {
        eprintln!("Error: {}\n", e);
        Args::command().print_help().unwrap();
    }
}

fn display_cache(args: Args) -> CCPResult<()> {
    let path = args
        .path
        .map(PathBuf::from)
        .or(default_cache_path())
        .ok_or(CCPError::CacheLocationCouldNotBeDetermined())?;

    // Parse date filter if provided
    let since_filter = args
        .since
        .as_ref()
        .map(|s| parse_date_filter(s))
        .transpose()?;

    // Parse size filter if provided
    let min_size_filter = args
        .min_size
        .as_ref()
        .map(|s| parse_size_filter(s))
        .transpose()?;

    // Parse extract directory if provided
    let extract_dir = args.extract.map(PathBuf::from);

    if let Some(ref since) = since_filter {
        let dt: DateTime<Local> = (*since).into();
        println!(
            "Filtering entries cached on or after: {}",
            dt.format("%Y-%m-%d")
        );
    }
    if let Some(min_size) = min_size_filter {
        println!("Filtering entries with file size >= {} bytes", min_size);
    }
    if let Some(ref dir) = extract_dir {
        println!("Will extract matching entries to: {}", dir.display());
        // Create the directory if it doesn't exist
        fs::create_dir_all(dir)?;
    }

    // Detect cache format and use appropriate parser
    if is_simple_cache(&path) {
        display_simple_cache(&path, args.silent, since_filter, min_size_filter, extract_dir)
    } else if is_block_file_cache(&path) {
        display_block_file_cache(&path, args.silent, since_filter, min_size_filter)
    } else {
        Err(CCPError::InvalidData(
            "Could not detect cache format (neither Simple Cache nor Block File)".to_string(),
        ))
    }
}

fn display_simple_cache(
    path: &PathBuf,
    silent: bool,
    since_filter: Option<SystemTime>,
    min_size_filter: Option<usize>,
    extract_dir: Option<PathBuf>,
) -> CCPResult<()> {
    println!("Detected: Simple Cache format");
    let cache = SimpleCache::from_path(path.clone())?;

    println!("Found {} entries in cache", cache.len());

    let entries = cache.entries()?;
    let mut displayed = 0;
    let mut filtered_out = 0;
    let mut extracted = 0;

    for entry_result in entries {
        match entry_result {
            Ok(entry) => {
                // Apply date filter if specified
                if let Some(ref since) = since_filter {
                    if let Some(file_time) = entry.file_modified {
                        if file_time < *since {
                            filtered_out += 1;
                            continue;
                        }
                    } else {
                        // Skip entries without a timestamp when filtering
                        filtered_out += 1;
                        continue;
                    }
                }

                // Apply size filter if specified (use file_size for accurate filtering)
                if let Some(min_size) = min_size_filter {
                    if (entry.file_size as usize) < min_size {
                        filtered_out += 1;
                        continue;
                    }
                }

                displayed += 1;

                if !silent {
                    // Format the file modification time
                    let time_str = entry
                        .file_modified
                        .map(|t| {
                            let dt: DateTime<Local> = t.into();
                            dt.format("%Y-%m-%d %H:%M:%S").to_string()
                        })
                        .unwrap_or_else(|| "unknown".to_string());

                    println!(
                        "[{}] [0x{:016x}] {}",
                        time_str,
                        entry.hash,
                        truncate_key(&entry.key, 80)
                    );
                    println!("\tfile size: {} bytes", entry.file_size);
                }

                // Extract if requested
                if let Some(ref dir) = extract_dir {
                    match extract_entry(&entry, dir) {
                        Ok(output_path) => {
                            extracted += 1;
                            if !silent {
                                println!("\t-> extracted to: {}", output_path.display());
                            }
                        }
                        Err(e) => {
                            eprintln!("\t-> extraction failed: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("\tError parsing entry: {}", e);
            }
        }
    }

    println!();
    if since_filter.is_some() || min_size_filter.is_some() {
        println!(
            "Matched {} entries (filtered out {})",
            displayed, filtered_out
        );
    } else {
        println!("Total: {} entries", displayed);
    }
    if extract_dir.is_some() {
        println!("Extracted {} files", extracted);
    }

    Ok(())
}

fn display_block_file_cache(
    path: &PathBuf,
    silent: bool,
    _since_filter: Option<SystemTime>,
    _min_size_filter: Option<usize>,
) -> CCPResult<()> {
    println!("Detected: Block File cache format");
    let cache = ChromeCache::from_path(path.clone())?;

    let entries = cache.entries()?;

    if !silent {
        let mut displayed = 0;

        for mut e in entries {
            if let Ok(cache_entry) = e.get() {
                displayed += 1;

                let time_str = cache_entry
                    .creation_time
                    .into_datetime_local()
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|_| "unknown".to_string());

                println!(
                    "[{}] [{:?}] {:?}",
                    time_str, cache_entry.hash, cache_entry.key
                );

                if let Ok(ranking) = e.get_rankings_node() {
                    if let Ok(r) = ranking.get() {
                        if let Ok(last_used) = r.last_used.into_datetime_local() {
                            println!("\tlast used: {}", last_used.format("%Y-%m-%d %H:%M:%S"));
                        }
                    }
                }
            }
        }

        println!("\nDisplayed {} entries", displayed);
    }

    Ok(())
}

fn truncate_key(key: &str, max_len: usize) -> String {
    if key.len() > max_len {
        format!("{}...", &key[..max_len])
    } else {
        key.to_string()
    }
}
