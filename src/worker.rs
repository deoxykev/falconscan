use crate::sql::{ArcPool, DB, ScanEntry};
use anyhow::{Result, bail};
use std::{path::Path, sync::Arc, fs};
use crate::crowdstrike::Crowdstrike;
use crate::crowdstrike::falconx::FalconSampleVerdict;
use goblin::{error, Object};

trait Scannable {
    fn is_unscannable(&self) -> Option<String>;
}
impl Scannable for ScanEntry {
    /// check if we can scan using CS api
    /// * will check filesize, extensions, and presence of elf, mach-o or PE magic bytes
    /// * returns Some(<unscannable_reason>)
    /// * returns None if it is scannable
    fn is_unscannable(&self) -> Option<String> {
        let max_filesize: u64 = 256000000;
        let min_filesize: u64 = 8;

        let file = Path::new(&self.path);
        if !file.exists() { return Some(String::from("file does not exist on disk anymore")) };
        if !file.is_file() { return Some(String::from("is not a valid file")) };
        if file.is_symlink() { return Some(String::from("file is a symlink")) };

        let meta_res = file.metadata();
        if meta_res.is_err() { return Some(String::from("could not get metadata for file")) }
        let meta = meta_res.unwrap();
        if meta.len() < min_filesize { return Some(String::from("file is less than 8 bytes skipped")) };
        if meta.len() > max_filesize { return Some(String::from("file is more than 256 MB skipped")) };

        let buffer_res = fs::read(file);
        if buffer_res.is_err() { return Some(String::from("could not read file from disk skipped")) };
        let buffer = buffer_res.unwrap();

        let ob = Object::parse(&buffer);
        if ob.is_ok() {
            match ob.unwrap() {
                Object::Archive(_) => return Some(String::from("file is an archive skipped")),
                Object::Elf(_) => return None,
                Object::Mach(_) => return None,
                Object::PE(_) => return None,
                Object::Unknown(_) => (),
            };
        }

        if let Some(ext) = &self.ext {
            match ext.trim() {
                "exe" => (),
                "dll" => (),
                "scr" => (),
                "pif" => (),
                "com" => (),
                "cpl" => (),
                "doc" => (),
                "docx" => (),
                "ppt" => (),
                "pps" => (),
                "pptx" => (),
                "ppsx" => (),
                "xls" => (),
                "xlsx" => (),
                "rtf" => (),
                "pub" => (),
                "pdf" => (),
                "apk" => (),
                "jar" => (),
                "sct" => (),
                "lmk" => (),
                "chm" => (),
                "hta" => (),
                "wsf" => (),
                "js" => (),
                "vbs" => (),
                "vbe" => (),
                "swf" => (),
                "pl" => (),
                "ps1" => (),
                "psm1" => (),
                "svg" => (),
                "py" => (),
                "eml" => (),
                "msg" => (),
                _ => return Some(String::from("sample type not supported")),
            }
        }
        None
    }
}

pub async fn execute(job: ScanEntry, pool: ArcPool, db: &'static DB, cs: Arc<Crowdstrike>) -> Result<()> {
    // println!("worker::execute - working on job: {}", &job.path);
    let mut job = job.clone();

    // check for scannability before submitting to CS
    if let Some(reason) = job.is_unscannable() {
        job.quickscan_verdict = Some(reason);
        job.quickscan_malicous = Some(Ok(false));
        println!("job is not scannable, skipping and marking as completed: {}", &job.path);
        db.finish_job(pool, job).await?;
        return Ok(())
    }

    let comment = format!("{} on {}", &job.file_name, &job.last_modified);

    let fqr = cs.falcon_quickscan(&job.path, &comment).await?;


    if let Some(sample) = fqr.samples
                            .iter()
                            .filter(|s| *s.sha256.as_ref().unwrap() == job.sha256)
                            .last()
    {

        if let Some(verdict) = &sample.verdict {
            println!("quickscan result: {} - {} - {:?} - {:?}", &fqr.cid, &job.file_name, sample.verdict, &sample.error);
            match verdict {
                FalconSampleVerdict::Clean => { 
                    job.quickscan_verdict = Some(String::from("clean"));
                    job.quickscan_malicous = Some(Ok(false));
                    },
                FalconSampleVerdict::PotentiallyUnwanted => {
                    job.quickscan_verdict = Some(String::from("potentially unwanted"));
                    job.quickscan_malicous = Some(Ok(true));
                },
                FalconSampleVerdict::Malware => {
                    job.quickscan_verdict = Some(String::from("malware"));
                    job.quickscan_malicous = Some(Ok(true));
                },
                FalconSampleVerdict::Unknown => {
                    job.quickscan_verdict = Some(String::from("unknown"));
                    job.quickscan_malicous = Some(Ok(false));
                }
            }
        }

        if let Some(error) = &sample.error {
            job.falconx_intel_verdict = Some(error.to_string());
            job.quickscan_malicous = Some(Ok(false));
        }
    } else {
        bail!("no verdict from api")
    }

    // println!("worker::execute - finished job: {}", &job.path);
    db.finish_job(pool, job).await?;
    Ok(())
}