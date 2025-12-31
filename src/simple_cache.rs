//! Simple Cache format parser for modern Chromium-based applications.
//!
//! The Simple Cache (also known as "Very Simple Backend") is the cache format
//! used by modern Chrome/Chromium browsers and Electron apps like Discord.
//!
//! Unlike the older Block File format, Simple Cache stores each entry in its own file.
//!
//! References:
//! - https://www.chromium.org/developers/design-documents/network-stack/disk-cache/very-simple-backend/
//! - https://chromium.googlesource.com/chromium/src/net/+/refs/heads/main/disk_cache/simple/

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::mem;
use std::path::{Path, PathBuf};

use zerocopy::{FromBytes, FromZeroes};

use crate::error::{CCPError, CCPResult};
use crate::time::WindowsEpochMicroseconds;

// Magic numbers from Chromium source
const SIMPLE_INDEX_MAGIC: u64 = 0xfcfb6d1ba7725c30;
const SIMPLE_ENTRY_MAGIC: u64 = 0xfcfb6d1ba7725c30;
const SIMPLE_EOF_MAGIC: u32 = 0xf4fa6f45;

// Simple Cache index versions we support
#[allow(dead_code)]
const SIMPLE_INDEX_VERSION_7: u32 = 7;
#[allow(dead_code)]
const SIMPLE_INDEX_VERSION_8: u32 = 8;
#[allow(dead_code)]
const SIMPLE_INDEX_VERSION_9: u32 = 9;

// Entry file format versions
const SIMPLE_ENTRY_VERSION_5: u32 = 5;
const SIMPLE_ENTRY_VERSION_9: u32 = 9;

/// Header for the Simple Cache index file.
/// Located at `<cache_dir>/index-dir/the-real-index`
#[derive(Debug, FromZeroes, FromBytes, Clone)]
#[repr(C, packed)]
pub struct SimpleIndexHeader {
    /// Magic number: 0xfcfb6d1ba7725c30
    pub magic: u64,
    /// Version of the index format
    pub version: u32,
}

#[allow(dead_code)]
const SIMPLE_INDEX_HEADER_SIZE: usize = mem::size_of::<SimpleIndexHeader>();

/// Entry metadata stored in the index file (version 7/8/9).
#[derive(Debug, FromZeroes, FromBytes, Clone)]
#[repr(C, packed)]
pub struct SimpleIndexEntry {
    /// Hash of the entry key (lower 64 bits)
    pub hash: u64,
    /// Last used time (Windows epoch microseconds)
    pub last_used_time: WindowsEpochMicroseconds,
    /// Size of the entry in bytes (data size, 24 bits used from u64)
    pub entry_size: u64,
}

#[allow(dead_code)]
const SIMPLE_INDEX_ENTRY_SIZE: usize = mem::size_of::<SimpleIndexEntry>();

/// Header at the start of each Simple Cache entry file.
#[derive(Debug, FromZeroes, FromBytes, Clone)]
#[repr(C, packed)]
pub struct SimpleEntryHeader {
    /// Magic number: 0xfcfb6d1ba7725c30
    pub magic: u64,
    /// Version of the entry format
    pub version: u32,
    /// Length of the key
    pub key_len: u32,
    /// Hash of the key (32-bit)
    pub key_hash: u32,
}

const SIMPLE_ENTRY_HEADER_SIZE: usize = mem::size_of::<SimpleEntryHeader>();

/// EOF record at the end of stream data.
#[derive(Debug, FromZeroes, FromBytes, Clone)]
#[repr(C, packed)]
pub struct SimpleEOFRecord {
    /// Magic number: 0xf4fa6f45
    pub magic: u32,
    /// Flags (has CRC, has key hash, etc.)
    pub flags: u32,
    /// CRC32 of the data (if flag set)
    pub data_crc: u32,
    /// Size of the stream
    pub stream_size: u32,
}

const SIMPLE_EOF_SIZE: usize = mem::size_of::<SimpleEOFRecord>();

/// Flags in the EOF record
pub mod eof_flags {
    pub const FLAG_HAS_CRC32: u32 = 1 << 0;
    pub const FLAG_HAS_KEY_SHA256: u32 = 1 << 1;
}

/// A parsed Simple Cache entry with its metadata and data.
#[derive(Debug)]
pub struct SimpleCacheEntry {
    /// The cache key (usually a URL)
    pub key: String,
    /// Hash of the entry
    pub hash: u64,
    /// Creation/last used time (from internal metadata, may be zero)
    pub last_used_time: WindowsEpochMicroseconds,
    /// File modification time (reliable timestamp for when entry was cached)
    pub file_modified: Option<std::time::SystemTime>,
    /// Total file size on disk (reliable indicator of cached content size)
    pub file_size: u64,
    /// HTTP headers (stream 0)
    pub headers_data: Vec<u8>,
    /// Response body (stream 1)
    pub body_data: Vec<u8>,
    /// Path to the entry file
    pub file_path: PathBuf,
}

impl SimpleCacheEntry {
    /// Get the HTTP headers as a string
    pub fn headers_string(&self) -> String {
        String::from_utf8_lossy(&self.headers_data).to_string()
    }
}

/// Iterator over Simple Cache entries.
pub struct SimpleCacheEntryIterator {
    entries: std::vec::IntoIter<(u64, PathBuf, WindowsEpochMicroseconds)>,
}

impl Iterator for SimpleCacheEntryIterator {
    type Item = CCPResult<SimpleCacheEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        let (hash, path, last_used) = self.entries.next()?;
        Some(parse_entry_file(&path, hash, last_used))
    }
}

/// A Simple Cache parser.
pub struct SimpleCache {
    path: PathBuf,
    entries: HashMap<u64, (PathBuf, WindowsEpochMicroseconds)>,
}

impl SimpleCache {
    /// Create a new SimpleCache from a cache directory path.
    pub fn from_path(path: PathBuf) -> CCPResult<SimpleCache> {
        let mut cache = SimpleCache {
            path: path.clone(),
            entries: HashMap::new(),
        };

        // Verify this is a Simple Cache by checking for the marker index file
        let index_marker = path.join("index");
        if index_marker.exists() {
            cache.verify_index_marker(&index_marker)?;
        }

        // Scan directory for entry files (the reliable method)
        // Note: the-real-index contains pickled/compressed data that would need
        // a Chromium pickle deserializer to parse, so we scan instead
        cache.scan_directory()?;

        Ok(cache)
    }
    
    /// Verify the index marker file has the correct magic number.
    fn verify_index_marker(&self, index_path: &Path) -> CCPResult<()> {
        let mut file = File::open(index_path)?;
        let mut buffer = [0u8; 12];
        
        if file.read(&mut buffer)? < 12 {
            return Err(CCPError::InvalidData(
                "Index marker file too small".to_string(),
            ));
        }
        
        let magic = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
        if magic != SIMPLE_INDEX_MAGIC {
            return Err(CCPError::InvalidData(format!(
                "Invalid simple cache index magic: 0x{:x}",
                magic
            )));
        }
        
        Ok(())
    }

    /// Scan the cache directory for entry files.
    fn scan_directory(&mut self) -> CCPResult<()> {
        let entries = fs::read_dir(&self.path)?;

        for entry in entries {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            // Simple cache entry files are named "<hash>_0" or "<hash>_s"
            if file_name_str.ends_with("_0") {
                if let Some(hash_str) = file_name_str.strip_suffix("_0") {
                    if let Ok(hash) = u64::from_str_radix(hash_str, 16) {
                        let file_path = entry.path();
                        // We'll get the real timestamp when parsing the entry
                        let dummy_time = WindowsEpochMicroseconds::default_value();
                        self.entries.insert(hash, (file_path, dummy_time));
                    }
                }
            }
        }

        Ok(())
    }

    /// Get an iterator over all cache entries.
    pub fn entries(&self) -> CCPResult<SimpleCacheEntryIterator> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .map(|(hash, (path, time))| (*hash, path.clone(), *time))
            .collect();

        Ok(SimpleCacheEntryIterator {
            entries: entries.into_iter(),
        })
    }

    /// Get a specific entry by its hash.
    pub fn get_entry(&self, hash: u64) -> CCPResult<SimpleCacheEntry> {
        let (path, time) = self
            .entries
            .get(&hash)
            .ok_or(CCPError::InvalidData(format!("Entry {} not found", hash)))?;

        parse_entry_file(path, hash, *time)
    }

    /// Get the number of entries in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Parse a Simple Cache entry file.
fn parse_entry_file(
    path: &Path,
    hash: u64,
    _last_used: WindowsEpochMicroseconds,
) -> CCPResult<SimpleCacheEntry> {
    // Get file metadata (modification time and size) before reading
    let metadata = fs::metadata(path).ok();
    let file_modified = metadata.as_ref().and_then(|m| m.modified().ok());
    let file_size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
    
    let mut file = BufReader::new(File::open(path)?);
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    if buffer.len() < SIMPLE_ENTRY_HEADER_SIZE {
        return Err(CCPError::InvalidData(
            "Entry file too small for header".to_string(),
        ));
    }

    let header = SimpleEntryHeader::ref_from(&buffer[0..SIMPLE_ENTRY_HEADER_SIZE])
        .ok_or(CCPError::DataMisalignment("simple entry header".to_string()))?;

    // Copy values from packed struct to avoid unaligned access
    let magic = { header.magic };
    let version = { header.version };
    
    if magic != SIMPLE_ENTRY_MAGIC {
        return Err(CCPError::InvalidData(format!(
            "Invalid entry magic: 0x{:x}",
            magic
        )));
    }
    if version != SIMPLE_ENTRY_VERSION_5 && version != SIMPLE_ENTRY_VERSION_9 {
        return Err(CCPError::UnsupportedVersion(format!(
            "Simple cache entry version {} not supported",
            version
        )));
    }

    let key_len = { header.key_len } as usize;
    let key_start = SIMPLE_ENTRY_HEADER_SIZE;
    let key_end = key_start + key_len;

    if buffer.len() < key_end {
        return Err(CCPError::InvalidData(
            "Entry file too small for key".to_string(),
        ));
    }

    let raw_key = String::from_utf8_lossy(&buffer[key_start..key_end]).to_string();
    // Clean up the key - strip leading null bytes and the "X/Y/" prefix used by Simple Cache
    let key = raw_key
        .trim_start_matches('\0')
        .trim_start_matches(|c: char| c.is_ascii_digit() || c == '/')
        .to_string();

    // Parse from the end to find EOF records
    // The file structure is:
    // [header][key][stream0_data][eof0][stream1_data][eof1]
    // or for version 9+:
    // [header][key][stream1_data][stream0_data][eof]
    
    let (headers_data, body_data, last_used_time) = if version >= SIMPLE_ENTRY_VERSION_9 {
        parse_entry_v9(&buffer, key_end)?
    } else {
        parse_entry_v5(&buffer, key_end)?
    };

    Ok(SimpleCacheEntry {
        key,
        hash,
        last_used_time,
        file_modified,
        file_size,
        headers_data,
        body_data,
        file_path: path.to_path_buf(),
    })
}

/// Find EOF magic positions in buffer by scanning
fn find_eof_positions(buffer: &[u8]) -> Vec<usize> {
    let pattern = SIMPLE_EOF_MAGIC.to_le_bytes();
    let mut positions = Vec::new();
    
    for i in 0..buffer.len().saturating_sub(3) {
        if buffer[i..i+4] == pattern {
            positions.push(i);
        }
    }
    positions
}

/// Parse entry format version 5 (format with separate EOF records per stream)
/// Structure: [header][key][key_hash?][eof0][metadata][stream1_data][eof1][padding?]
fn parse_entry_v5(
    buffer: &[u8],
    key_end: usize,
) -> CCPResult<(Vec<u8>, Vec<u8>, WindowsEpochMicroseconds)> {
    // Find all EOF magic positions
    let eof_positions = find_eof_positions(buffer);
    
    if eof_positions.is_empty() {
        return Err(CCPError::InvalidData(
            "No EOF records found in entry".to_string(),
        ));
    }

    // The last EOF in the file is for stream 1 (the main data)
    let eof1_start = *eof_positions.last().unwrap();
    
    if eof1_start + SIMPLE_EOF_SIZE > buffer.len() {
        return Err(CCPError::InvalidData(
            "EOF record extends past end of file".to_string(),
        ));
    }

    let eof1 = SimpleEOFRecord::ref_from(&buffer[eof1_start..eof1_start + SIMPLE_EOF_SIZE])
        .ok_or(CCPError::DataMisalignment("EOF record 1".to_string()))?;

    // Copy values from packed struct to avoid unaligned access
    let stream1_size = { eof1.stream_size } as usize;
    
    // Stream 1 data ends at the EOF1 position
    let stream1_end = eof1_start;
    let stream1_start = stream1_end.saturating_sub(stream1_size);
    
    // Extract stream 1 data (this is typically the HTTP response: headers + body)
    let body_data = if stream1_start < stream1_end && stream1_start >= key_end {
        buffer[stream1_start..stream1_end].to_vec()
    } else {
        Vec::new()
    };

    // Stream 0 is typically empty or contains minimal metadata
    // For simplicity, we'll skip extracting it separately since the HTTP data is in stream 1
    let headers_data = Vec::new();

    Ok((headers_data, body_data, WindowsEpochMicroseconds::default_value()))
}

/// Parse entry format version 9 (newer format)
/// Uses the same approach as v5 - find EOF by scanning
fn parse_entry_v9(
    buffer: &[u8],
    key_end: usize,
) -> CCPResult<(Vec<u8>, Vec<u8>, WindowsEpochMicroseconds)> {
    // Use the same parsing as v5
    parse_entry_v5(buffer, key_end)
}

/// Trait extension for WindowsEpochMicroseconds
impl WindowsEpochMicroseconds {
    pub fn default_value() -> Self {
        // Return a zero timestamp - we'll need to handle this in display
        unsafe { std::mem::zeroed() }
    }
}

/// Check if a cache directory uses Simple Cache format.
pub fn is_simple_cache(path: &Path) -> bool {
    // Simple cache has an index-dir subdirectory
    let index_dir = path.join("index-dir");
    if index_dir.exists() {
        return true;
    }

    // Or has files matching the pattern "<16-hex-chars>_0"
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with("_0") && name_str.len() == 18 {
                // 16 hex chars + "_0"
                return true;
            }
        }
    }

    false
}

/// Check if a cache directory uses Block File format.
pub fn is_block_file_cache(path: &Path) -> bool {
    // Block file cache has an "index" file and "data_X" files
    let index_file = path.join("index");
    if !index_file.exists() {
        return false;
    }

    // Check if index file is large enough for block file format (368 bytes)
    if let Ok(metadata) = fs::metadata(&index_file) {
        metadata.len() >= 368
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_sizes() {
        assert_eq!(SIMPLE_INDEX_HEADER_SIZE, 12);
        assert_eq!(SIMPLE_ENTRY_HEADER_SIZE, 20);
        assert_eq!(SIMPLE_EOF_SIZE, 16);
    }
}

