use std::{
    path::Path,
    sync::Arc,
};

use anyhow::{Result, Context, anyhow, bail};
use serde::{Deserialize, Serialize};
use tokio::{fs::File};
use crate::crowdstrike::Crowdstrike;
use reqwest::{Body};
use tokio_util;


/// Used in `Crowdstrike::falcon_x_submission_quota()`
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FalconXSubmissionQuotaResponse {
    meta: Meta,
    errors: Vec<CSError>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CSError {
    code: u64,
    message: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Meta {
    #[serde(rename = "query_time")]
    query_time: f64,
    #[serde(rename = "powered_by")]
    powered_by: Option<String>,
    #[serde(rename = "trace_id")]
    trace_id: String,
    quota: Option<Quota>,
    pagination: Option<Pagination>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pagination {
    limit: i64,
    offset: i64,
    total: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quota {
    pub total: i64,
    pub used: i64,
    #[serde(rename = "in_progress")]
    pub in_progress: i64,
}


impl Crowdstrike {
     /// Get the falcon x quickscan submission quota usage
    pub async fn falcon_quickscan_submission_quota(&self) -> Result<Quota> {
        let a = Arc::clone(&self.auth_token);
        let auth_token = a.lock().await;

        let res = self.client.get(
            // format!("https://{}/falconx/entities/submissions/v1?ids=", &self.base_url))
            format!("https://{}/scanner/entities/scans/v1?ids=", &self.base_url))
            .header("Authorization", format!("bearer {}", &auth_token))
            .send().await?
            .json::<FalconXSubmissionQuotaResponse>().await
                .with_context(||"failed to deserialize FalconXSubmissionQuotaResponse")?;

        if let Some(quota) = res.meta.quota {
            let s = Arc::clone(&self.quickscan_quota);
            let mut sandbox_quota = s.lock().await;
            *sandbox_quota = quota.clone();
            Ok(quota)
        } else {
            Err(Crowdstrike::fmt_err(res.errors, res.meta, "falcon_quickscan_submission_quota"))
        }
    }

     /// Get the falcon x sandbox submission quota usage
    pub async fn falcon_sandbox_submission_quota(&self) -> Result<Quota> {
        let a = Arc::clone(&self.auth_token);
        let auth_token = a.lock().await;

        let res = self.client.get(
            // format!("https://{}/falconx/entities/submissions/v1?ids=", &self.base_url))
            format!("https://{}/falconx/entities/submissions/v1?ids=", &self.base_url))
            .header("Authorization", format!("bearer {}", &auth_token))
            .send().await?
            .json::<FalconXSubmissionQuotaResponse>().await
                .with_context(||"failed to deserialize FalconXSubmissionQuotaResponse")?;

        if let Some(quota) = res.meta.quota {
            let s = Arc::clone(&self.sandbox_quota);
            let mut sandbox_quota = s.lock().await;
            *sandbox_quota = quota.clone();
            Ok(quota)
        } else {
            Err(Crowdstrike::fmt_err(res.errors, res.meta, "falcon_sandbox_submission_quota"))
        }
    }

    // Submit a file to quickscan, detonate & poll results until a verdict is reached
    pub async fn falcon_quickscan(&self, file_path: &str, comment: &str) -> Result<FalconSampleResult> {
        // println!("uploading...");
        let sha256 = self.falcon_quickscan_upload(file_path, comment).await?;
        // println!("uploading...done");

        // println!("detonating...");
        let quickscan_id = self.falcon_quickscan_detonate(&sha256).await?;
        // println!("detonating...done");

        loop {
            tokio::time::sleep(
                tokio::time::Duration::from_millis(500)
            ).await;

            // println!("polling results...");
            let res = self.falcon_quickscan_results(&quickscan_id.as_str()).await?;
            // println!("polling results...done");
            match res.status {
                FalconSampleStatus::Created => println!("created {:?}", res),
                FalconSampleStatus::Pending => println!("pending {:?}", res),
                FalconSampleStatus::Unknown => println!("uknown: {:?}", res),
                FalconSampleStatus::Done => return Ok(res),
            }
            // if res.status { return Ok(res)}
        }
    }

    // pub async fn falcon_quickscan_upload_filetype()

    /// Submit files to falcon x quickscan (max size 256MB)
    /// Returns a SHA256 hash to pass into falcon_quickscan_detonate()
    /// ### Valid file formats
    /// - Portable executables: .exe, .dll.
    /// - Office documents: .doc, .docx, .ppt, .pptx, .pptm, .xls, .xlsx, .xlsm
    /// - PDF
    /// - Linux ELF executables
    /// - MacOS Mach-O executables
    pub async fn falcon_quickscan_upload(&self, file_path: &str, comment: &str) -> Result<String> {
        // check file
        let path = Path::new(file_path);

        let file_name = path.file_name()
            .with_context(||"invalid file name")?;

        if !path.exists() { 
            bail!("File does not exist: {}", path.to_str().ok_or(
                anyhow!("Filename not valid"))?
            )
        }
        let file_handle = File::open(path).await?;
        let file_size = file_handle.metadata().await?.len();

        let max_filesize: u64 = 256000000;
        if file_size > max_filesize {
            bail!("file size greater than 256MB: {}", path.to_str().unwrap_or("unknown"))
        }

        let a = Arc::clone(&self.auth_token);
        let auth_token = a.lock().await;

        Ok(
            self.client.post(
            format!("https://{}/samples/entities/samples/v3", self.base_url))
            .header("Authorization", format!("bearer {}", auth_token))
            .header("Content-Type", "application/octet-stream")
            .query(&[("file_name", file_name.to_str())])
            .query(&[("comment", comment)])
            .query(&[("is_confidential", "true")])
            .body(
                Body::wrap_stream(
                    tokio_util::io::ReaderStream::new( // dont load file into memory
                        // File::open(path).await?
                        file_handle
                    )
                ))
            .send().await?
            .json::<FalconSampleUploadResult>().await
            .with_context(||"could not deserialize upload response from CS api")?
            .get_resources()?
            .sha256
        )
    }

    /// detonates a SHA256 sample, returns the ID
    /// upload the sample with falcon_quickscan_upload() first
    async fn falcon_quickscan_detonate(&self, sha256: &str) -> Result<String> {
        let a = Arc::clone(&self.auth_token);
        let auth_token = a.lock().await;
        let payload = &Samples{ samples: vec!(sha256.to_string())};

        self.client.post(
            format!("https://{}/scanner/entities/scans/v1", self.base_url))
            .header("Authorization", format!("bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .json(payload)
            .send().await?
            .json::<FalconSampleDetonateResult>().await
            .with_context(||"could not deserialize detonate response from CS api")?
            .get_resources()
    }

    /// get results from quickscan id
    /// detonate the sample first with falcon_quickscan_detonate() and pass in the ID
    async fn falcon_quickscan_results(&self, quickscan_id: &str) -> Result<FalconSampleResult> {
        let a = Arc::clone(&self.auth_token);
        let auth_token = a.lock().await;

            tokio::time::sleep(
                tokio::time::Duration::from_millis(2000)
            ).await;

        let mut result = self.client.get(
            format!("https://{}/scanner/entities/scans/v1", self.base_url))
            .header("Authorization", format!("bearer {}", auth_token))
            .header("Content-Type", "application/json")
            .query(&[("ids", quickscan_id)])
            .send().await?
            .json::<FalconSamplePollResults>().await?;

        // retry a few times in case we race faster than the API
        let mut retry = 10;
        while result.resources.is_empty() || retry > 0 {
            tokio::time::sleep(
                tokio::time::Duration::from_millis(500)
            ).await;
            result = self.client.get(
                format!("https://{}/scanner/entities/scans/v1", self.base_url))
                .header("Authorization", format!("bearer {}", auth_token))
                .header("Content-Type", "application/json")
                .query(&[("ids", quickscan_id)])
                .send().await?
                .json::<FalconSamplePollResults>().await?;
            retry -= 1;
        }

        // update internal state of quota
        if let Some(quota) = &result.meta.quota {
            let s = Arc::clone(&self.quickscan_quota);
            let mut sandbox_quota = s.lock().await;
            *sandbox_quota = quota.clone();
        }

        result.get_resources()
    }


    /// Formats crowdstrike API error message
    /// ## Usage
    /// ```
    /// use function_name::named;
    /// #[named]
    /// ...
    /// Err(Crowdstrike::fmt_err(res.errors, res.meta, function_name!()))
    /// ```
    fn fmt_err(errors: Vec<CSError>, meta: Meta, context: &str)
        -> anyhow::Error {

        anyhow!
        (
            "Code: {} while calling: {}()\nTrace ID: {}",
                errors
                    .into_iter()
                    .fold(String::from(""), |acc, err| {
                        format!("{}{} - {}\n", acc, &err.code, &err.message)
                    }),
                context,
                meta.trace_id,
        )
    }

}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FalconSampleUploadResult {
    pub meta: Meta,
    pub resources: Vec<Sample>,
    pub errors: Vec<CSError>,
}

impl FalconSampleUploadResult {
    fn get_resources(&self) -> Result<Sample> {
        if !self.errors.is_empty() {
            return Err(Crowdstrike::fmt_err(
                self.errors.clone(),
                self.meta.clone(),
                "falcon_sample_upload",
            ))
        }

        if let Some(sample) = self.resources.first() {
            return Ok(sample.to_owned())
        } else {
            bail!("FalconSampleUploadResult.get_resources(): no sample resources returned by api")
        };
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sample {
    sha256: String,
    #[serde(rename = "file_name")]
    file_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize)]
struct Samples {
    samples: Vec<String> 
}




#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FalconSampleDetonateResult {
    pub meta: Meta,
    pub resources: Vec<String>,
    pub errors: Vec<CSError>,
}

impl FalconSampleDetonateResult {
    fn get_resources(&self) -> Result<String> {
        if !self.errors.is_empty() {
            return Err(Crowdstrike::fmt_err(
                self.errors.clone(),
                self.meta.clone(),
                "falcon_sample_detonate",
            ))
        }

        if let Some(sample) = self.resources.first() {
            return Ok(sample.to_owned())
        } else {
            bail!("FalconSampleDetonateResult.get_resources(): no sample resources returned by api")
        };
    }
}


// get quickscan detonate results
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FalconSamplePollResults {
    errors: Vec<CSError>,
    meta: Meta,
    resources: Vec<FalconSampleResult>,
}

impl FalconSamplePollResults {
    fn get_resources(&self) -> Result<FalconSampleResult> {
        if !self.errors.is_empty() {
            return Err(Crowdstrike::fmt_err(
                self.errors.clone(),
                self.meta.clone(),
                "falcon_sample_results",
            ))
        }

        if let Some(sample) = self.resources.first() {
            return Ok(sample.to_owned())
        } else {
            bail!("FalconSamplePollResults.get_resources(): no sample resources returned by api")
        };
    }
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FalconSampleResult {
    pub cid: String,
    #[serde(rename = "created_timestamp")]
    pub created_timestamp: String,
    pub id: String,
    pub samples: Vec<FalconSample>,
    pub status: FalconSampleStatus, // "done", "created", "pending"
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FalconSampleStatus {
    Done,
    Created,
    Pending,
    Unknown,
}
impl Default for FalconSampleStatus {
    fn default() -> Self { FalconSampleStatus::Unknown }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FalconSample {
    pub error: Option<String>, // "sample type not supported"
    pub sha256: Option<String>,
    pub verdict: Option<FalconSampleVerdict>, // "no specific threat", "unknown", "malware"
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FalconSampleVerdict {
    #[serde(rename = "no specific threat")]
    Clean,
    #[serde(rename = "potentially unwanted")]
    PotentiallyUnwanted,
    Malware,
    Unknown,
}
impl Default for FalconSampleVerdict {
    fn default() -> Self { FalconSampleVerdict::Unknown }
}


#[cfg(test)]
mod tests {
    use crate::Crowdstrike;

    #[tokio::test]
    async fn test_quickscan_submission_quota() {
        let cs = Crowdstrike::new(
            String::from("api.crowdstrike.com"),
            String::from("xxxxxxxxxxxxxxxxxxx"),
            String::from("xxxxxxxxxxxxxxxxxx"),
            reqwest::Client::new() 
        ).await.unwrap();

        let quota = cs.falcon_quickscan_submission_quota().await.unwrap();        
        println!("quickscan quota: {:?}", quota);
    }

    #[tokio::test]
    async fn test_sandbox_submission_quota() {
        let cs = Crowdstrike::new(
            String::from("api.crowdstrike.com"),
            String::from("xxxxxxxxxxxxxxxxxxx"),
            String::from("xxxxxxxxxxxxxxxxxx"),
            reqwest::Client::new() 
        ).await.unwrap();

        let quota = cs.falcon_sandbox_submission_quota().await.unwrap();        
        println!("sandbox quota: {:?}", quota);
    }

    #[tokio::test]
    async fn test_quickscan_upload() {
        let cs = Crowdstrike::new(
            String::from("api.crowdstrike.com"),
            String::from("xxxxxxxxxxxxxxxxxxx"),
            String::from("xxxxxxxxxxxxxxxxxx"),
            reqwest::Client::new() 
        ).await.unwrap();
        let sha = cs.falcon_quickscan_upload("./SharpHound.exe", "foo").await.unwrap();
        println!("{sha}");
    }

    #[tokio::test]
    async fn test_falcon_quickscan_detonate() {
        let cs = Crowdstrike::new(
            String::from("api.crowdstrike.com"),
            String::from("xxxxxxxxxxxxxxxxxxx"),
            String::from("xxxxxxxxxxxxxxxxxx"),
            reqwest::Client::new() 
        ).await.unwrap();
        let id = cs.falcon_quickscan_detonate("f1c45cbbd98619e197154085a05fd972283af6788343aa04492e35798a06e2b7").await
            .expect("quickscan detonate fail");
        println!("{id}");
    }

    #[tokio::test]
    async fn test_falcon_quickscan_results() {
        let cs = Crowdstrike::new(
            String::from("api.crowdstrike.com"),
            String::from("xxxxxxxxxxxxxxxxxxx"),
            String::from("xxxxxxxxxxxxxxxxxx"),
            reqwest::Client::new() 
        ).await.unwrap();
        let res = cs.falcon_quickscan_results("20e1775307a74e63adcb902f603b8f10_0d673ff637634e35a56e7c0f7d042050").await
            .expect("quickscan results fail");

        println!("{:?}", res);
    }

    #[tokio::test]
    async fn test_falcon_quickscan() {
        let cs = Crowdstrike::new(
            String::from("api.crowdstrike.com"),
            String::from("xxxxxxxxxxxxxxxxxxx"),
            String::from("xxxxxxxxxxxxxxxxxx"),
            reqwest::Client::new() 
        ).await.unwrap();
        // todo: check for file-size 400 - Invalid file size, maximum file size is 256000000 bytes
        let res = cs.falcon_quickscan("./testsamples/mimikatz.exe", "testing").await
            .expect("quickscan results fail");

        println!("{:?}", res);
    }
}