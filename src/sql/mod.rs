mod sql;
use anyhow::{Result, Context, bail, anyhow};
use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};

use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc};
use chrono::{self, DateTime, Utc};
use rusqlite::{self, params};
use r2d2::{self, Pool};
use r2d2_sqlite::{self, SqliteConnectionManager};
// use crate::crowdstrike::falconx;



#[derive(Debug)]
pub struct ScanEntry {
    pub id: Option<i64>,
    pub sha256: String,
    pub path: String,
    pub last_modified: DateTime<Utc>,
    pub file_name: String,
    pub ext: Option<String>,
    pub falconx_intel_malicious: Option<Result<bool>>,
    pub quickscan_malicous: Option<Result<bool>>,
    pub falconx_intel_verdict: Option<String>,
    pub quickscan_verdict: Option<String>,
    pub dt: DateTime<Utc>,
    pub in_progess: bool,
    pub complete: bool,
}
impl Clone for ScanEntry {
    fn clone(&self) -> ScanEntry {

        let fim = if let Some(f) = self.falconx_intel_malicious.as_ref() {
            // idk sorry
            let val = if f.is_err() { false } else { if *f.as_ref().unwrap() { true } else { false } };
            Some(Ok(val))
        } else {
            None
        };
        let qsm = if let Some(f) = self.quickscan_malicous.as_ref() {
            // compiler why you do this to me 
            let val = if f.is_err() { false } else { if *f.as_ref().unwrap() { true } else { false } };
            Some(Ok(val))
        } else {
            None
        };

        ScanEntry {
            id: self.id.clone(), 
            sha256: self.sha256.clone(),
            path: self.path.clone(),
            last_modified: self.last_modified.clone(),
            file_name: self.file_name.clone(),
            ext: self.ext.clone(),
            falconx_intel_malicious: fim,
            quickscan_malicous: qsm,
            falconx_intel_verdict: self.falconx_intel_verdict.clone(),
            quickscan_verdict: self.quickscan_verdict.clone(),
            dt: self.dt.clone(),
            in_progess: self.in_progess.clone(),
            complete: self.complete.clone(),
        }
    }
}

impl ScanEntry {
    pub fn new(path: &PathBuf)  -> Result<Self> {
        // check file
        let p = path; 
        let full_path = p.canonicalize()?.to_string_lossy().to_string();

        let file_name = p.file_name()
            .with_context(||"invalid file name")?
            .to_string_lossy()
            .to_string();

        if !p.exists() { 
            bail!("File does not exist: {}", p.to_str().ok_or(
                anyhow!("Filename not valid"))?
            )
        }

        // check file ext
        let ext: String = p 
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();

        let mut ext_opt = None;
        if !ext.is_empty() {
            ext_opt = Some(ext);
        }

        // get last modified date
        let lm: chrono::DateTime<Utc> =
             p.metadata()
             .with_context(||"could not fetch file metadata while creating file entry")?
             .modified()
             .with_context(||"could not fetch modified time while creating file entry")?
             .into();

        Ok(ScanEntry {
            id: None,
            sha256: sha256_digest(path)?, 
            path: full_path,
            last_modified: lm,
            file_name,
            ext: ext_opt, 
            falconx_intel_malicious: None,
            quickscan_malicous: None,
            falconx_intel_verdict: None,
            quickscan_verdict: None,
            dt: chrono::Utc::now(),
            in_progess: false,
            complete: false,
        })
    }

}

/// calculates sha256 digest as lowercase hex string
fn sha256_digest(path: &PathBuf) -> Result<String> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);

    let digest = {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 { break }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    Ok(HEXLOWER.encode(digest.as_ref()))
}

trait BoolString {
    fn to_int_string(&self) -> String;
}

/// convert Option<Result<Bool>> into a sqlite ready "0" or "1" value
impl BoolString for core::option::Option<Result<bool, anyhow::Error>> {
    fn to_int_string(&self) -> String {
        if let Some(val) = self {
            if *val.as_ref().unwrap_or(&false) {
                String::from("1")
            } else {
                String::from("0")
            }
        }
        else { String::from("0") }
    }
}

impl BoolString for bool {
    fn to_int_string(&self) -> String {
        if *self { String::from("1") }
        else     { String::from("0") }
    }
}

trait OptionStr {
    fn to_sql_str(&self) -> &str;
}
impl OptionStr for Option<String> {
    fn to_sql_str(&self) -> &str {
        if let Some(val) = self {
            val.as_str()
        } else {
            "NULL"
        }
    }
}

// yolo?
// unsafe impl Send for DB {}
// unsafe impl Sync for DB {}

pub struct DB {
    // pool: Arc<Pool<SqliteConnectionManager>>
    // conn: Arc<Mutex<rusqlite::Connection>>,
}
    struct C {
        cnt: i64
    }

pub type ArcPool = Arc<Pool<SqliteConnectionManager>>;

impl DB {
    pub fn new<'a>(db_path: &str) -> Result<&'a Self> {
    // let manager = r2d2_sqlite::SqliteConnectionManager::file("foo.sqlite");
    // let pool = r2d2::Pool::builder()
    //     .max_size(20)
    //     .build(manager)?;
    //     let conn = pool.get()?;
    //     DB::init_db(&conn)?;
    // let pool = Arc::new(pool);
        let conn = rusqlite::Connection::open(db_path)?;
        DB::init_db(&conn)?;
        Ok( &DB {} )
    }

    fn init_db(conn: &rusqlite::Connection) -> Result<()> {
        conn.execute("
            create table if not exists files (
                id integer primary key,
                sha256 char(32) not null,
                path text not null unique,
                last_modified datetime,
                file_name text not null,
                ext text not null,
                falconx_intel_malicious bool,
                quickscan_malicious bool,
                falconx_intel_verdict text,
                quickscan_verdict text,
                dt datetime,
                in_progress bool,
                complete bool
            )
        ",[])?;

        conn.execute("UPDATE files set
                        in_progress = false
                      WHERE in_progress = true"
                    ,[])?;

        Ok(())
    }

    /// Takes the next uncompleted item, marking it as in_progress
    /// * will check to see there is already a matching filehash with completed entry
    pub async fn take_job(&self, pool: ArcPool) -> Result<Option<ScanEntry>> {
        let conn = pool.get()?;
        let mut stmt = conn.prepare("SELECT id, sha256, path, last_modified, file_name, ext,
                                          falconx_intel_malicious, quickscan_malicious,
                                          falconx_intel_verdict, quickscan_verdict,
                                          dt, in_progress, complete
                                          FROM files
                                          WHERE complete = false AND in_progress = false
                                          LIMIT 1
                                        ")?;

        let res_iter = stmt.query_map([], |row| {
            let complete: bool = row.get(12)?;

            let falconx_intel_verdict: Option<String> = 
                if complete { 
                    let x = row.get(8)?;
                    if x == "NULL" { None 
                    } else { Some(x) }
                } else {
                    None
                };

            let quickscan_verdict: Option<String> = 
                if complete { 
                    let x = row.get(9)?;
                    if x == "NULL" { None 
                    } else { Some(x) }
                } else {
                    None
                };

            let falconx_intel_malicious: Option<Result<bool>> = 
                if complete && falconx_intel_verdict.is_some() {
                    Some(Ok(row.get(6)?))
                } else {
                    None
                };

            let quickscan_malicious: Option<Result<bool>> = 
                if complete && quickscan_verdict.is_some() {
                    Some(Ok(row.get(7)?))
                } else {
                    None
                };


            let res = ScanEntry{
                id: row.get(0)?,
                sha256: row.get(1)?,
                path: row.get(2)?,
                last_modified: row.get(3)?,
                file_name: row.get(4)?,
                ext: row.get(5)?,
                falconx_intel_malicious,
                quickscan_malicous: quickscan_malicious,
                falconx_intel_verdict,
                quickscan_verdict,
                dt: row.get(10)?,
                in_progess: true, // hardcode true because we update it later
                complete,
            };

            Ok(res)
        })?;

        let res = res_iter
            .last()
            .transpose()?;

        // mark dupes as in_progress too
        if let Some(r) = &res {
            conn.execute("UPDATE files set in_progress = true WHERE sha256 = (?1)", [&r.sha256])?;
        }

        Ok(res)
    }

    pub async fn reset_jobs(&self, pool: ArcPool) -> Result<()> {
        pool.get()?
            .execute("UPDATE files set in_progress = false WHERE in_progress = true", [])
            .with_context(||"failed to reset in_progress in all rows")?;
        Ok(())
    }

    pub async fn finish_job(&self, pool: ArcPool, scan_result: ScanEntry) -> Result<()> {
        let conn = pool.get()?;
        // self.delete(pool, &scan_result.id.unwrap()).await?;

        // self.insert(pool, scan_result).await?;

        let mut stmt = conn.prepare("
            UPDATE files set
                    in_progress = :in_progress,
                    complete = :complete,
                    falconx_intel_malicious = :falconx_intel_malicious,
                    falconx_intel_verdict = :falconx_intel_verdict,
                    quickscan_verdict = :quickscan_verdict,
                    quickscan_malicious = :quickscan_malicious,
                    dt = :dt
            WHERE sha256 = :sha256
        ")?;

        // todo add chrono
        stmt.execute(&[
            (":in_progress", "0"),
            (":complete", "1"),
            (":falconx_intel_malicious", scan_result.falconx_intel_malicious.to_int_string().as_str()), 
            (":falconx_intel_verdict", scan_result.falconx_intel_verdict.to_sql_str()),
            (":quickscan_verdict", scan_result.quickscan_verdict.to_sql_str()),
            (":quickscan_malicious", scan_result.quickscan_malicous.to_int_string().as_str()),
            (":sha256", scan_result.sha256.as_str()),
            (":dt", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.6f%z").to_string().as_str()),
        ])?;


        Ok(())
    }


    pub async fn active_jobs(&self, pool: ArcPool) -> Result<i64> {
            let conn = pool.get()?;
            let mut stmt = conn.prepare("select COUNT(DISTINCT sha256) from files WHERE in_progress = true")?;
            Ok(stmt.query_row::<i64,_,_>([], |r| r.get(0))?)
    }



    /// Checks if file already exists, inserting it if it doesn't
    /// * if file already exists, check if file has been modified
    /// * if file has been modified, insert a new uncompleted entry
    /// * will clone quickscan results from another entry if the filehash is the same
    pub async fn check_file(&self, pool: ArcPool, path: PathBuf) -> Result<()> {

        // let p = &path; 
        // let full_path = p.canonicalize()?.to_string_lossy().to_string();
        // println!("checkfile: {full_path}");

        let lfile = self.lookup_file(pool.clone(), &path).await?;
        Ok(
            match lfile {
            Some(mut scan_entry) => {
                let p = Path::new(&path);
                if !p.exists() { 
                    bail!("File does not exist: {}", p.to_str().ok_or(
                        anyhow!("Filename not valid"))?
                    )
                }

                // get last modified date
                let lm: chrono::DateTime<Utc> =
                    p.metadata()
                    .with_context(||"could not fetch file metadata while creating file entry")?
                    .modified()
                    .with_context(||"could not fetch modified time while creating file entry")?
                    .into();


                // check for file metadata changes 
                // println!("lm1 {} - lm2 {}", &scan_entry.last_modified, &lm);
                if scan_entry.last_modified == lm {
                    return Ok(())
                }
                scan_entry.last_modified = lm;

                // check for file content changes
                let current_filehash = sha256_digest(&path)?;

                // println!("sha1 {} - sha2 {}", &current_filehash, &scan_entry.sha256);
                if scan_entry.sha256 == current_filehash {
                    return Ok(())
                }
                scan_entry.sha256 = current_filehash;

                println!("marking uncompleted for rescan: {}", &scan_entry.path);
                // mark uncompleted for rescan
                scan_entry.complete = false;
                scan_entry.falconx_intel_malicious = None;
                scan_entry.falconx_intel_verdict = None;
                scan_entry.quickscan_malicous = None;
                scan_entry.quickscan_verdict = None;
                scan_entry.dt = chrono::Utc::now(); 


                if let Some(id) = scan_entry.id {
                    self.delete(pool.clone(), &id).await?;
                } else {
                    bail!("sql ID is missing during update row procedure");
                }

                self.insert(pool.clone(), scan_entry).await?
            }

            None => {
                let mut entry = ScanEntry::new(&path)?;
                if let Some(dupe) = self.check_dupe(pool.clone(), &path).await? {
                    entry.falconx_intel_malicious = dupe.falconx_intel_malicious;
                    entry.falconx_intel_verdict = dupe.falconx_intel_verdict;
                    entry.quickscan_malicous = dupe.quickscan_malicous;
                    entry.quickscan_verdict = dupe.quickscan_verdict;
                    entry.complete = dupe.complete;
                }
                println!("adding new file to queue: {:?}", &path);
                self.insert(pool.clone(), entry).await?
            }
        }
        )
    }

    pub async fn check_dupe(&self, pool: ArcPool, path: &PathBuf) -> Result<Option<ScanEntry>> {
        let current_hash = sha256_digest(path);
        let entries_with_hash = self.lookup_hash(pool, current_hash?.as_str()).await?;
        if entries_with_hash.is_none() {
            return Ok(None)
        }

        Ok(
            entries_with_hash.unwrap()
            .into_iter()
            .filter(|e| e.complete)
            .last()
        )
    }

    pub async fn delete(&self, pool: ArcPool, id: &i64) -> Result<()> {
        let conn = pool.get()?;
        conn.execute("DELETE FROM files WHERE id = (?1)", [id])?;
        Ok(())
    }

    pub async fn update(&self, pool: ArcPool, mut entry: ScanEntry) -> Result<()> {
        if let Some(id) = entry.id {
            self.delete(pool.clone(), &id).await?;
        } else {
            bail!("sql ID is missing during update row procedure");
        };
        entry.dt = chrono::Utc::now();
        self.insert(pool.clone(), entry).await
    }

    pub async fn lookup_hash(&self, pool: ArcPool, sha256: &str) -> Result<Option<Vec<ScanEntry>>> {
        let conn = pool.get()?;
        let mut stmt = conn.prepare("SELECT id, sha256, path, last_modified, file_name, ext,
                                          falconx_intel_malicious, quickscan_malicious,
                                          falconx_intel_verdict, quickscan_verdict,
                                          dt, in_progress, complete
                                          FROM files WHERE sha256=:sha256")?;

        let res_iter = stmt.query_map(&[(":sha256", sha256)], |row| {
            let complete: bool = row.get(12)?;


            let falconx_intel_verdict: Option<String> = 
                if complete { 
                    let x = row.get(8)?;
                    if x == "NULL" { None 
                    } else { Some(x) }
                } else {
                    None
                };

            let quickscan_verdict: Option<String> = 
                if complete { 
                    let x = row.get(9)?;
                    if x == "NULL" { None 
                    } else { Some(x) }
                } else {
                    None
                };

            let falconx_intel_malicious: Option<Result<bool>> = 
                if complete && falconx_intel_verdict.is_some() {
                    Some(Ok(row.get(6)?))
                } else {
                    None
                };

            let quickscan_malicious: Option<Result<bool>> = 
                if complete && quickscan_verdict.is_some() {
                    Some(Ok(row.get(7)?))
                } else {
                    None
                };


            let res = ScanEntry{
                id: row.get(0)?,
                sha256: row.get(1)?,
                path: row.get(2)?,
                last_modified: row.get(3)?,
                file_name: row.get(4)?,
                ext: row.get(5)?,
                falconx_intel_malicious,
                quickscan_malicous: quickscan_malicious,
                falconx_intel_verdict,
                quickscan_verdict,
                dt: row.get(10)?,
                in_progess: row.get(11)?,
                complete,
            };

            Ok(res)
        })?;


        let res: Vec<ScanEntry> = res_iter
            .map(|r| r.unwrap())
            .collect();

        if res.len() == 0 {
            Ok(None)
        } else {
            Ok(Some(res))
        }
    }

    pub async fn lookup_file(&self, pool: ArcPool, path: &PathBuf) -> Result<Option<ScanEntry>> {
        let p = path; 
        let full_path = p.canonicalize()?.to_string_lossy().to_string();

        let conn = pool.get()?;
        let mut stmt = conn.prepare("SELECT id, sha256, path, last_modified, file_name, ext,
                                          falconx_intel_malicious, quickscan_malicious,
                                          falconx_intel_verdict, quickscan_verdict,
                                          dt, in_progress, complete
                                          FROM files WHERE path=:path")?;

        let res_iter = stmt.query_map(&[(":path", full_path.as_str())], |row| {
            let complete: bool = row.get(12)?;


            let falconx_intel_verdict: Option<String> = 
                if complete { 
                    let x = row.get(8)?;
                    if x == "NULL" { None 
                    } else { Some(x) }
                } else {
                    None
                };

            let quickscan_verdict: Option<String> = 
                if complete { 
                    let x = row.get(9)?;
                    if x == "NULL" { None 
                    } else { Some(x) }
                } else {
                    None
                };

            let falconx_intel_malicious: Option<Result<bool>> = 
                if complete && falconx_intel_verdict.is_some() {
                    Some(Ok(row.get(6)?))
                } else {
                    None
                };

            let quickscan_malicious: Option<Result<bool>> = 
                if complete && quickscan_verdict.is_some() {
                    Some(Ok(row.get(7)?))
                } else {
                    None
                };


            let res = ScanEntry{
                id: row.get(0)?,
                sha256: row.get(1)?,
                path: row.get(2)?,
                last_modified: row.get(3)?,
                file_name: row.get(4)?,
                ext: row.get(5)?,
                falconx_intel_malicious,
                quickscan_malicous: quickscan_malicious,
                falconx_intel_verdict,
                quickscan_verdict,
                dt: row.get(10)?,
                in_progess: row.get(11)?,
                complete,
            };

            Ok(res)
        })?;

        Ok(res_iter.last().transpose()?)
    }

    pub async fn insert(&self, pool: ArcPool, entry: ScanEntry) -> Result<()> {
        let conn = pool.get()?;
        conn.execute(
                "INSERT into files
                    (
                        sha256, path, last_modified,
                        file_name, ext,
                        falconx_intel_malicious,
                        quickscan_malicious,
                        falconx_intel_verdict,
                        quickscan_verdict,
                        dt, in_progress, complete
                    ) 
                    values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                "
            , params![
                &entry.sha256, &entry.path, &entry.last_modified,
                &entry.file_name, &entry.ext.unwrap_or_default(),
                &entry.falconx_intel_malicious.to_int_string(),
                &entry.quickscan_malicous.to_int_string(),
                &entry.falconx_intel_verdict.unwrap_or("NULL".to_string()),
                &entry.quickscan_verdict.unwrap_or("NULL".to_string()),
                &entry.dt, &entry.in_progess.to_int_string(),
                &entry.complete.to_int_string(),
                ]
        )?;

        Ok(())
    }

}

mod test {
    use crate::sql::DB;
    use crate::sql::ScanEntry;
    use std::fs::OpenOptions;
    use std::io::prelude::*;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;

    use super::sha256_digest;

    #[tokio::test]
    async fn test_init() {
        let manager = r2d2_sqlite::SqliteConnectionManager::file("foo.sqlite");
        let pool = r2d2::Pool::builder()
            .max_size(20)
            .build(manager)
            .expect("failed to build pool");
        let pool = Arc::new(pool);
        let db = DB::new("foo.sqlite")
            .expect("failed to init sqlite db");

        let file: PathBuf = Path::new("./Sharphound.exe").into();
        let file2 = &file.clone();

        db.check_file(pool.clone(), file)
                .await
                .expect("could not create file entry");


        db.insert(
            pool.clone(),
            ScanEntry::new(&file2)
                .expect("could not create file entry")
            )
            .await
            .expect_err("expected fail on duplicate entry");
    }

    #[tokio::test]
    async fn test_dupe() {
        let manager = r2d2_sqlite::SqliteConnectionManager::file("foo.sqlite");
        let pool = r2d2::Pool::builder()
            .max_size(20)
            .build(manager)
            .expect("failed to build pool");
        let pool = Arc::new(pool);
        let db = DB::new("foo.sqlite")
            .expect("failed to init sqlite db");

        let file: PathBuf = Path::new("./Sharphound2.exe").into();
        let file2 = &file.clone();

        db.check_file(pool.clone(), file)
                .await
                .expect("could not create file entry");


        let x = db.lookup_file(pool.clone(), &file2)
            .await
            .expect("failed to lookup file");

        match x {
            None => panic!("should have returned something"),
            Some(x) => println!("{:?}", x)
        } 
    }


    #[tokio::test]
    async fn test_lookup() {
        let manager = r2d2_sqlite::SqliteConnectionManager::file("foo.sqlite");
        let pool = r2d2::Pool::builder()
            .max_size(20)
            .build(manager)
            .expect("failed to build pool");
        let pool = Arc::new(pool);
        let db = DB::new("foo.sqlite")
            .expect("failed to init sqlite db");
        // db.check_file("/Users/k/git/falconscan/SharpHound.exe")
        //     .expect("file check fail");

        let file = Path::new("./Sharphound.exe").into();
        let x = db.lookup_file(pool.clone(), &file)
            .await
            .expect("failed to lookup file");

        match x {
            None => panic!("should have returned something"),
            Some(x) => println!("{:?}", x)
        } 

        let file2 = Path::new("/Users/k/git/falconscan/target/asdf").into();
        let x = db.lookup_file(pool.clone(), &file2)
            .await
            .expect("failed to lookup file");

        match x {
            None => panic!("should have returned something"),
            Some(x) => println!("{:?}", x)
        } 

    }

    #[tokio::test]
    async fn test_modify() {
        let manager = r2d2_sqlite::SqliteConnectionManager::file("foo.sqlite");
        let pool = r2d2::Pool::builder()
            .max_size(20)
            .build(manager)
            .expect("failed to build pool");
        let pool = Arc::new(pool);
        let db = DB::new("foo.sqlite")
            .expect("failed to init sqlite db");
        
        // let f = "/Users/k/git/falconscan/SharpHound.exe";
        let f = Path::new("./Sharphound.exe").into();

        let d1 = db.lookup_file(pool.clone(), &f)
            .await
            .expect("failed to lookup file 1");

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&f)
            .expect("failed to open file for writing");

        writeln!(file, "x")
            .expect("failed to write to file");

        let f2 = f.clone();
        let f3 = f.clone();

        db.check_file(pool.clone(), f2)
            .await
            .expect("failed to check file");

        let d2 = db.lookup_file(pool.clone(), &f3)
            .await
            .expect("failed to lookup file 1");

        assert_ne!(d2.unwrap().sha256, d1.unwrap().sha256)
    }

    #[tokio::test]
    async fn test_update() {
        let manager = r2d2_sqlite::SqliteConnectionManager::file("foo.sqlite");
        let pool = r2d2::Pool::builder()
            .max_size(20)
            .build(manager)
            .expect("failed to build pool");
        let pool = Arc::new(pool);
        let db = DB::new("foo.sqlite")
            .expect("failed to init sqlite db");
        
        let f = Path::new("./Sharphound.exe").into();

        let mut d1: ScanEntry = db.lookup_file(pool.clone(), &f)
            .await
            .expect("failed to lookup file 1")
            .unwrap();

        d1.complete = true;
        d1.quickscan_verdict = Some("foobar".to_string());
        db.update(pool.clone(), d1)
            .await
            .expect("failed to update status");
        
        let u1 = db.lookup_file(pool.clone(), &f)
            .await
            .expect("failed to lookup file 1 after update")
            .unwrap();

        assert!(u1.complete == true)

    }

    #[tokio::test]
    async fn test_active_jobs() {
        let manager = r2d2_sqlite::SqliteConnectionManager::file("foo.sqlite");
        let pool = r2d2::Pool::builder()
            .max_size(20)
            .build(manager)
            .expect("failed to build pool");
        let pool = Arc::new(pool);
        let db = DB::new("foo.sqlite")
            .expect("failed to init sqlite db");

        db.take_job(pool.clone()).await
            .expect("failed to take a job");
        db.take_job(pool.clone()).await
            .expect("failed to take a job");

        let cnt = db.active_jobs(pool.clone()).await
                    .expect("active jobs query failed");

        assert_eq!(2, cnt);
    }

    #[test]
    fn test_sha256() {
        let path = Path::new("./pika.jpg").into();
        let digest = sha256_digest(&path)
            .expect("digest calc failed");

        println!("{}", digest);
        assert_eq!(digest, "cf0a9e747ad5c76b88837d4f1f996eed8f8c40fd0147b69ad20b67314ba7c075".to_string());
    }

}