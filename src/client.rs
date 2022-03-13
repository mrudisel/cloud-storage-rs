//! Clients for Google Cloud Storage endpoints.

use std::fmt;

use crate::token::TokenCache;

mod bucket;
mod bucket_access_control;
mod default_object_access_control;
mod hmac_key;
mod object;
mod object_access_control;

pub use bucket::BucketClient;
pub use bucket_access_control::BucketAccessControlClient;
pub use default_object_access_control::DefaultObjectAccessControlClient;
pub use hmac_key::HmacKeyClient;
pub use object::ObjectClient;
pub use object_access_control::ObjectAccessControlClient;

/// The primary entrypoint to perform operations with Google Cloud Storage.
pub struct Client {
    client: reqwest::Client,
    /// Static `Token` struct that caches
    token_cache: Box<dyn crate::TokenCache>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("client", &self.client)
            .field("token_cache", &"<opaque>")
            .finish()
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Constructs a client with the default token provider, where it attemps to obtain the
    /// credentials from the following locations:
    ///
    /// 1. Checks for the environment variable `SERVICE_ACCOUNT`, and if it exists, reads the file
    /// at the path specified there as a credentials json file.
    /// 2. It attemps to do the same with the `GOOGLE_APPLICATION_CREDENTIALS` var.
    /// 3. It reads the `SERVICE_ACCOUNT_JSON` environment variable directly as json and uses that
    /// 4. It attemps to do the same with the `GOOGLE_APPLICATION_CREDENTIALS_JSON` var.
    pub fn new() -> Self {
        #[cfg(feature = "reqwest/trust-dns")]
        let client = reqwest::Client::builder()
            .trust_dns()
            .build()
            .expect("could not build reqwest client");

        #[cfg(not(feature = "reqwest/trust-dns"))]
        let client = reqwest::Client::builder()
            .build()
            .expect("could not build reqwest client");

        Self { client, token_cache: Box::new(crate::Token::default()) }
    }

    /// Initializer with a provided refreshable token
    pub fn with_cache(token: impl TokenCache + 'static) -> Self {
        Self {
            client: Default::default(),
            token_cache: Box::new(token),
        }
    }

    /// Operations on [`Bucket`](crate::bucket::Bucket)s.
    pub fn bucket(&self) -> BucketClient<'_> {
        BucketClient(self)
    }

    /// Operations on [`BucketAccessControl`](crate::bucket_access_control::BucketAccessControl)s.
    pub fn bucket_access_control(&self) -> BucketAccessControlClient<'_> {
        BucketAccessControlClient(self)
    }

    /// Operations on [`DefaultObjectAccessControl`](crate::default_object_access_control::DefaultObjectAccessControl)s.
    pub fn default_object_access_control(&self) -> DefaultObjectAccessControlClient<'_> {
        DefaultObjectAccessControlClient(self)
    }

    /// Operations on [`HmacKey`](crate::hmac_key::HmacKey)s.
    pub fn hmac_key(&self) -> HmacKeyClient<'_> {
        HmacKeyClient(self)
    }

    /// Operations on [`Object`](crate::object::Object)s.
    pub fn object(&self) -> ObjectClient<'_> {
        ObjectClient(self)
    }

    /// Operations on [`ObjectAccessControl`](crate::object_access_control::ObjectAccessControl)s.
    pub fn object_access_control(&self) -> ObjectAccessControlClient<'_> {
        ObjectAccessControlClient(self)
    }

    async fn get_headers(&self) -> crate::Result<reqwest::header::HeaderMap> {
        let mut result = reqwest::header::HeaderMap::new();
        let token = self.token_cache.get(&self.client).await?;
        result.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
        Ok(result)
    }
}
