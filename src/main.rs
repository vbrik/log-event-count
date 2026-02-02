use chrono::offset::Local;
use chrono::{Datelike, NaiveDateTime, TimeZone};
use clap::Parser;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogStateEntry {
    inode: u64,
    pos: u64,
}

type LogState = HashMap<String, LogStateEntry>;

#[derive(Parser, Debug, Serialize)]
#[command(
    name = "log-event-count",
    version,
    about = "A check_mk MRPE plugin that reports the number of lines containing \
     SUBSTRING in LOGFILE that occurred within last MINUTES. The script may \
     undercount slightly.",
)]
struct Args {
    /// Metric label for perfdata graph
    #[arg()]
    metric: String,

    /// Log files to read
    #[arg(long, value_name = "LOGFILE", num_args = 1..)]
    logfiles: Vec<String>,

    /// Strings to match
    #[arg(long, value_name = "SUBSTRING", num_args = 1.. )]
    strings: Vec<String>,

    /// Timestamp strptime format
    #[arg(long, value_name = "FORMAT")]
    ts_fmt: String,

    /// Number of space-separated fields before timestamp begins
    #[arg(long, value_name = "NUM", default_value_t = 0)]
    ts_offset: usize,

    /// Interval time in minutes
    #[arg(long, value_name = "MINUTES", default_value_t = 60)]
    interval: i64,

    /// Warning and critical threshold
    #[arg(long, value_name = "NUM", num_args = 2,
    default_values_t = [f64::INFINITY, f64::INFINITY])]
    thresholds: Vec<f64>,

    /// Use this as current time instead of time()
    #[arg(long, value_name = "SECONDS")]
    now: Option<i64>,

    /// Process at most this many MB of data at the tail end of log file.
    #[arg(long, value_name = "MB", default_value_t = 20)]
    input_limit: u64,
}

fn extract_ts_fields(line: &str, offset: usize, num_elts: usize) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if offset >= parts.len() {
        return None;
    }
    let end = std::cmp::min(parts.len(), offset + num_elts);
    if offset >= end {
        return None;
    }
    Some(parts[offset..end].join(" "))
}
fn parse_timestamp_local(line: &str, fmt: &str, offset: usize) -> Option<i64> {
    let num_elts = fmt.split_whitespace().count();
    let ts_str = extract_ts_fields(line, offset, num_elts)?;

    let naive = if fmt.contains("%Y") {
        NaiveDateTime::parse_from_str(&ts_str, fmt).ok()?
    } else {
        let year = Local::now().year();
        let ts2 = format!("{} {}", year, ts_str);
        let fmt2 = format!("%Y {}", fmt);
        NaiveDateTime::parse_from_str(&ts2, &fmt2).ok()?
    };

    let dt = Local.from_local_datetime(&naive).single()?;
    Some(dt.timestamp())
}
fn count_matches(
    substrings: &[String],
    file_name: &str,
    start_pos: u64,
    now: i64,
    interval_minutes: i64,
    ts_fmt: &str,
    ts_offset: usize,
) -> io::Result<(u64, u64)> {
    let mut count: u64 = 0;

    let f = File::open(file_name)?;
    let mut reader = BufReader::new(f);

    reader.seek(SeekFrom::Start(start_pos))?;

    let mut lookbehind: VecDeque<String> = VecDeque::with_capacity(100);

    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }

        lookbehind.push_back(line.clone());
        if lookbehind.len() > 100 {
            lookbehind.pop_front();
        }

        if substrings.iter().any(|s| line.contains(s)) {
            // Try timestamp from this line; otherwise scan backward in lookbehind.
            let mut ts = parse_timestamp_local(&line, ts_fmt, ts_offset).unwrap_or(0);
            if ts == 0 {
                for prev in lookbehind.iter().rev() {
                    if let Some(t) = parse_timestamp_local(prev, ts_fmt, ts_offset) {
                        ts = t;
                        break;
                    }
                }
            }

            let last_ts = ts;

            if now - ts < interval_minutes * 60 {
                count += 1;
            }
            if last_ts > now {
                break;
            }
        }
    }

    let end_pos = reader.stream_position()?;
    Ok((count, end_pos))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn save_state(path: &PathBuf, state: &LogState) -> io::Result<()> {
    let bytes =
        bincode::serialize(state).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut f = File::create(path)?;
    f.write_all(&bytes)?;
    Ok(())
}

fn load_state(path: &PathBuf) -> io::Result<LogState> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.is_empty() {
                Ok(LogState::new())
            } else {
                bincode::deserialize::<LogState>(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(LogState::new()),
        Err(e) => Err(e),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("args = {:?}", args);

    let warn_threshold = args.thresholds.get(0).copied().unwrap_or(f64::INFINITY);
    let crit_threshold = args.thresholds.get(1).copied().unwrap_or(f64::INFINITY);

    if warn_threshold > crit_threshold {
        eprintln!("Warning threshold is greater than critical threshold");
        std::process::exit(1);
    }
    let now = args.now.unwrap_or_else(|| Local::now().timestamp());
    let input_size_limit = args.input_limit * (1u64 << 20);

    let args_bytes = bincode::serialize(&args).expect("Args serialization must not fail");
    let args_hash = hash_bytes(&args_bytes);
    let state_path = PathBuf::from(format!("/tmp/{}_{}", args.metric, args_hash));
    let mut log_state = load_state(&state_path)?;

    println!("{} {}", args_hash, state_path.display());

    // Reconcile state vs filesystem (missing files, rotations, truncations, tail-limits).
    for logfile in &args.logfiles {
        let md = match fs::metadata(logfile) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log_state.remove(logfile);
                continue;
            }
            Err(e) => return Err(Box::new(e)),
        };

        let inode = md.ino();
        let size = md.len();

        match log_state.get_mut(logfile) {
            None => {
                log_state.insert(logfile.clone(), LogStateEntry { inode, pos: 0 });
            }
            Some(ent) => {
                if ent.inode != inode {
                    *ent = LogStateEntry { inode, pos: 0 };
                } else if ent.pos > size {
                    ent.pos = 0;
                }
            }
        }
        // Apply input-limit tail rule.
        if let Some(ent) = log_state.get_mut(logfile) {
            if size.saturating_sub(ent.pos) > input_size_limit {
                ent.pos = size.saturating_sub(input_size_limit);
            }
        }
    }
    save_state(&state_path, &log_state)?;

    let mut match_count: u64 = 0;

    // Iterate over the keys we currently have in state (like the Python code).
    let keys: Vec<String> = log_state.keys().cloned().collect();
    for logfile in keys {
        let start_pos = log_state.get(&logfile).map(|e| e.pos).unwrap_or(0);

        let (count, end_pos) = match count_matches(
            &args.strings,
            &logfile,
            start_pos,
            now,
            args.interval,
            &args.ts_fmt,
            args.ts_offset,
        ) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // File disappeared between reconciliation and scan.
                log_state.remove(&logfile);
                save_state(&state_path, &log_state)?;
                continue;
            }
            Err(e) => return Err(Box::new(e)),
        };

        match_count += count;

        if let Some(ent) = log_state.get_mut(&logfile) {
            ent.pos = end_pos;
        }
        save_state(&state_path, &log_state)?;
    }

    println!(
        "{} matching lines within last {} minute(s)|{}={}",
        match_count, args.interval, args.metric, match_count
    );

    if (match_count as f64) >= crit_threshold {
        std::process::exit(2);
    }
    if (match_count as f64) >= warn_threshold {
        std::process::exit(1);
    }

    Ok(())
}
