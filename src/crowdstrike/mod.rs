use reqwest;
use anyhow::{Result, Context};
use serde::{Deserialize};
use serde_with::{serde_as, DurationSeconds};
use std::collections::HashMap;
use std::env;
use chrono::{DateTime, Utc, Duration};
use tokio::sync::Mutex;
use std::sync::Arc;

use self::falconx::Quota;
pub mod falconx;

pub struct Crowdstrike {
    base_url: String,
    client_secret: String,
    client_id: String,
    auth_token: Arc<Mutex<String>>,
    auth_token_expiration: Arc<Mutex<DateTime<Utc>>>,
    client: reqwest::Client,
    quickscan_quota: Arc<Mutex<Quota>>,
    sandbox_quota: Arc<Mutex<Quota>>,
}

#[serde_as]
#[derive(Deserialize, Debug)]
/// Used in `Crowdstrike::get_auth_token`
pub struct AuthTokenResponse {
    access_token: String,
    #[serde_as(as = "DurationSeconds<i64>")]
    expires_in: Duration,
}

impl Crowdstrike {
    /// Creates a new API client for Crowdstrike
    /// # Arguments Example
    /// - `base_url`: api.crowdstrike.com
    /// - `client_secret`: xxxxx
    /// - `client_id`: xxxxx
    /// - `client`: reqwest::Client::new()
    pub async fn new(base_url: String, client_secret: String, client_id: String, client: reqwest::Client) -> Result<Crowdstrike> {
        let auth = Crowdstrike::get_auth_token(&base_url, &client_id, &client_secret).await?;

        let auth_token_expiration = Arc::new(Mutex::new(
            Utc::now()
                .checked_add_signed(auth.expires_in) // api returns offset in seconds
                .with_context(||"could not convert auth token expiration timestamp")?
        ));

        let auth_token = Arc::new(Mutex::new(
            auth.access_token
        ));

        let quickscan_quota = Arc::new(Mutex::new(
            Quota::default()
        ));
        let sandbox_quota = quickscan_quota.clone();

        Ok(Self { 
            base_url,client_id,
            client_secret, client,
            auth_token, auth_token_expiration,
            quickscan_quota, sandbox_quota,
        })
    }

    /// Creates a new API client for Crowdstrike from environment variables
    /// # Environment Variables
    /// - `CS_BASE_URL`: base URL used for CS API; defaults to api.us-2.crowdstrike.com
    /// - `CS_CLIENT_SECRET`: oauth client secret
    /// - `CS_CLIENT_PROXY`: http proxy address (optional)
    /// - `CS_ID`: oauth client id
    pub async fn from_env() -> Result<Crowdstrike> {
        let default_base_url = String::from("api.crowdstrike.com");
        let base_url = env::var("CS_BASE_URL")
            .unwrap_or(default_base_url);

        let client_secret = env::var("CS_CLIENT_SECRET")
            .with_context(||"CS_CLIENT_SECRET env variable is unset")?;

        let client_id = env::var("CS_CLIENT_ID")
            .with_context(||"CS_CLIENT_ID env variable is unset")?;

        let client = match env::var_os("CS_CLIENT_PROXY") {
            None => reqwest::Client::new(),
            Some(addr) => reqwest::Client::builder()
                            .proxy(reqwest::Proxy::https("http://127.0.0.1:8080")?)
                            .danger_accept_invalid_certs(true)
                            .build()?
        };

        Crowdstrike::new(base_url, client_secret, client_id, client).await
    }

    // // get initial auth token
    async fn get_auth_token(base_url: &str, client_id: &str, client_secret: &str) -> Result<AuthTokenResponse> {
        reqwest::Client::new()
            .post(format!("https://{}/oauth2/token", base_url))
            .header("Accept", "application/json")
            .form(&{
                let mut form = HashMap::new();
                form.insert("client_id", client_id);
                form.insert("client_secret", client_secret);
                form
            })
            .send().await
            .with_context(||"Failed to issue access token - Not Authorized")?
            .json::<AuthTokenResponse>().await
            .with_context(||"Failed to deserialize auth token response")
    }

    // /// Refreshes the CS auth token if it expires within 5 minutes
    pub async fn refresh_auth_token(&self) -> Result<()> {
        let a = Arc::clone(&self.auth_token_expiration);
        let mut auth_token_expiration = a.lock().await;

        let auth_token_expires_soon = auth_token_expiration
                .checked_sub_signed(Duration::minutes(5))
                .with_context(||"Failed to calculate auth token expiration during token refresh op")?
                .gt(&Utc::now());

        if !auth_token_expires_soon { return Ok(()) }

        let b = Arc::clone(&self.auth_token);
        let mut auth_token = b.lock().await;


        println!("refeshing auth token...");
        let auth = self.client.post(
            format!("https://{}/oauth2/token", &self.base_url))
            .header("Accept", "application/json")
            .form(&{
                let mut form = HashMap::new();
                form.insert("client_id", &self.client_id);
                form.insert("client_secret", &self.client_secret);
                form
            })
            .send().await
            .with_context(||"Failed to issue access token - Not Authorized")?
            .json::<AuthTokenResponse>().await
            .with_context(||"Failed to deserialize auth token response")?;

        let new_auth_token_expiration = Utc::now()
            .checked_add_signed(auth.expires_in)
            .with_context(||"Failed to calculate auth token expiration during token refresh op")?;

        
        // update self.auth token info
        *auth_token_expiration = new_auth_token_expiration;
        *auth_token = auth.access_token;
        Ok(())
    }
}

// #[cfg(test)]
mod tests {
    use crate::Crowdstrike;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_get_auth_token() {
        let cs = Crowdstrike::from_env().await.unwrap();

        println!("auth_token: {}", Arc::clone(&cs.auth_token).lock().await);
        println!("expiration: {}", Arc::clone(&cs.auth_token_expiration).lock().await);
    }
}