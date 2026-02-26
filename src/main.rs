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
use std::process::{ExitCode, Termination};
use std::string::ToString;

const MAX_LOOKBEHIND: usize = 100;

#[repr(u32)]
enum NagiosCode {
    Ok = 0,
    Warning = 1,
    Critical = 2,
    Unknown = 3,
}

impl Termination for NagiosCode {
    fn report(self) -> ExitCode {
        ExitCode::from(self as u8)
    }
}

/// Log file scanning cursor structure that passes state between invocations.
/// Enables detection of file rotations, truncation, and skipping entries
/// that are too old.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogCursor {
    /// Inode of the log file this cursor tracks
    inode: u64,
    /// Hint where to start scanning the next time we are executed
    start_pos_hint: u64,
    // XXX for truncations, need so save some bytes at start_pos
    //start_pos_bytes: Vec<u8>,
}

// Put this in a module so it can't be mutated even in this module
// (to force correct field initialization)
mod timestamp_spec {
    pub struct TimestampSpec {
        /// strftime format of the timestamp
        format: String,
        /// Number of space-separated fields before timestamp begins
        start_field_index: usize,
        /// Number of (whitespace-separated) fields in format
        num_fields: usize,
    }

    impl TimestampSpec {
        pub fn new(format: String, start_field_index: usize) -> Self {
            let num_fields = format.split_whitespace().count();
            Self {
                format,
                start_field_index,
                num_fields,
            }
        }
        pub fn format(&self) -> &str {
            &self.format // note implicit cast (self.format wouldn't work)
        }
        pub fn start_field_index(&self) -> usize {
            self.start_field_index
        }
        pub fn num_fields(&self) -> usize {
            self.num_fields
        }
    }
}
use timestamp_spec::TimestampSpec;

type LogState = HashMap<String, LogCursor>;

#[derive(Parser, Debug, Serialize)]
#[command(
    name = "log-event-count",
    about = "A check_mk MRPE plugin that reports the number of lines containing \
     SUBSTRING in LOGFILE that occurred within last MINUTES."
)]
struct Args {
    /// Metric label for check_mk perfdata graph
    #[arg()]
    metric: String,

    /// Log file(s) to read
    #[arg(long, value_name = "PATH", num_args = 1..)]
    logfiles: Vec<String>,

    /// String(s) to match in log lines
    #[arg(long, value_name = "STRING", num_args = 1.. )]
    strings: Vec<String>,

    /// Timestamp's strptime format
    #[arg(long, value_name = "FORMAT", default_value = "%a %b %e %H:%M:%S %Y")]
    ts_fmt: String,

    /// Index (starting from 0) of the (whitespace-separated) field where the timestamp begins
    #[arg(long, value_name = "NUM", default_value_t = 0)]
    ts_idx: usize,

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

pub fn skip_whitespace(cursor: &mut usize, bytes: &[u8]) {
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
}

fn skip_field(cursor: &mut usize, bytes: &[u8]) {
    while *cursor < bytes.len() && !bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
}

fn extract_ts2<'a>(line: &'a str, ts_spec: &TimestampSpec) -> Option<&'a str> {
    let ts_first: usize;
    let mut cursor = 0usize;
    let mut fields_found = 0usize;
    let bytes = line.as_bytes();

    loop {
        skip_whitespace(&mut cursor, bytes);
        if cursor >= bytes.len() {
            return None;
        }
        fields_found += 1;
        if fields_found == ts_spec.start_field_index() + 1 {
            ts_first = cursor;
            break;
        }
        skip_field(&mut cursor, bytes);
    }

    loop {
        skip_field(&mut cursor, bytes);
        if fields_found == ts_spec.start_field_index() + ts_spec.num_fields() {
            return Some(&line[ts_first..cursor]);
        }
        skip_whitespace(&mut cursor, bytes);
        if cursor >= bytes.len() {
            return None;
        }
        fields_found += 1;
    }
}

fn parse_ts_local(line: &str, ts_spec: &TimestampSpec) -> Option<i64> {
    let ts_str = extract_ts2(line, ts_spec)?;

    let naive = if ts_spec.format().contains("%Y") {
        NaiveDateTime::parse_from_str(ts_str, ts_spec.format()).ok()?
    } else {
        let year = Local::now().year();
        let ts2 = format!("{} {}", year, ts_str);
        let fmt2 = format!("%Y {}", ts_spec.format());
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
    ts_spec: &TimestampSpec,
) -> io::Result<(u64, u64)> {
    let mut count: u64 = 0;
    let mut first_match_pos = 0;

    let f = File::open(file_name)?;
    let mut reader = BufReader::new(f);
    reader.seek(SeekFrom::Start(start_pos))?;

    let mut multiline_context: VecDeque<String> = VecDeque::with_capacity(MAX_LOOKBEHIND);

    let mut line = String::new();
    'iter_lines: loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }

        multiline_context.push_back(line.clone());
        if multiline_context.len() > MAX_LOOKBEHIND {
            multiline_context.pop_front();
        }

        if substrings.iter().any(|s| line.contains(s)) {
            // Try timestamp from this line; otherwise scan backward in lookbehind.
            let ts = match parse_ts_local(&line, ts_spec).or_else(|| {
                multiline_context
                    .iter()
                    .rev()
                    .find_map(|prev_line| parse_ts_local(prev_line, ts_spec))
            }) {
                Some(ts) => ts,
                None => {
                    continue 'iter_lines;
                }
            };

            if ts > now {
                break;
            }
            if now - ts < interval_minutes * 60 {
                if count == 0 {
                    first_match_pos = reader.stream_position()?;
                }
                count += 1;
            }
        }
    }

    if first_match_pos > 0 {
        Ok((count, first_match_pos))
    } else {
        Ok((count, start_pos))
    }
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

fn main() -> Result<NagiosCode, Box<dyn std::error::Error>> {
    let args = Args::parse();
    println!("args = {:?}", args);

    let warn_threshold = args.thresholds.first().copied().unwrap_or(f64::INFINITY);
    let crit_threshold = args.thresholds.get(1).copied().unwrap_or(f64::INFINITY);

    if warn_threshold > crit_threshold {
        eprintln!("Warning threshold is greater than critical threshold");
        return Ok(NagiosCode::Unknown);
    }
    let now = args.now.unwrap_or_else(|| Local::now().timestamp());
    let input_size_limit = args.input_limit * (1u64 << 20);

    let args_bytes = bincode::serialize(&args).expect("Args serialization must not fail");
    let args_hash = hash_bytes(&args_bytes);
    let state_path = PathBuf::from(format!("/tmp/{}_{}", args.metric, args_hash));
    let mut log_state = load_state(&state_path)?;
    let ts_spec = TimestampSpec::new(args.ts_fmt.clone(), args.ts_idx);

    println!("{} {}", args_hash, state_path.display());

    // Reconcile state vs filesystem (missing files, rotations, truncations, tail-limits).
    // This is race. It should be done after we have a handle for the logfile
    for logfile in &args.logfiles {
        let logfile_md = match fs::metadata(logfile) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log_state.remove(logfile);
                println!("{}", logfile);
                continue;
            }
            Err(e) => return Err(Box::new(e)),
        };

        let inode = logfile_md.ino();
        let size = logfile_md.len();

        match log_state.get_mut(logfile) {
            None => {
                log_state.insert(
                    logfile.clone(),
                    LogCursor {
                        inode,
                        start_pos_hint: 0,
                    },
                );
            }
            Some(ent) => {
                if ent.inode != inode {
                    *ent = LogCursor {
                        inode,
                        start_pos_hint: 0,
                    };
                } else if ent.start_pos_hint > size {
                    ent.start_pos_hint = 0;
                }
            }
        }
        // Apply input-limit tail rule.
        if let Some(ent) = log_state.get_mut(logfile)
            && size.saturating_sub(ent.start_pos_hint) > input_size_limit
        {
            ent.start_pos_hint = size.saturating_sub(input_size_limit);
        }
    }
    save_state(&state_path, &log_state)?;

    let mut match_count: u64 = 0;

    // Iterate over the keys we currently have in state
    let keys: Vec<String> = log_state.keys().cloned().collect();
    for logfile in keys {
        let start_pos = log_state
            .get(&logfile)
            .map(|e| e.start_pos_hint)
            .unwrap_or(0);

        let (count, start_pos_hint) = match count_matches(
            &args.strings,
            &logfile,
            start_pos,
            now,
            args.interval,
            &ts_spec,
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
            ent.start_pos_hint = start_pos_hint;
        }
        save_state(&state_path, &log_state)?;
    }

    println!(
        "{} matching lines within last {} minute(s)|{}={}",
        match_count, args.interval, args.metric, match_count
    );

    if (match_count as f64) >= crit_threshold {
        Ok(NagiosCode::Critical)
    } else if (match_count as f64) >= warn_threshold {
        Ok(NagiosCode::Warning)
    } else {
        Ok(NagiosCode::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_whitespace() {
        let cases = vec![
            (0, 1, " x "),
            (0, 4, " \n\t "),
            (0, 0, "x "),
            (1, 3, "x  "),
            (1, 1, " "),
        ];
        let mut cursor;

        for (start, target, str) in cases {
            cursor = start;
            skip_whitespace(&mut cursor, str.as_bytes());
            assert_eq!(cursor, target);
        }
    }
}
