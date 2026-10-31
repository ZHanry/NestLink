//! Typed directory management; these responses grant no network/IP access.
use super::{Method, Sdk, SdkError, base, resource};
use nestlink_protocol::spaces::addressing::*;

impl Sdk {
    pub async fn space_address_directory(
        &self,
        space: &str,
    ) -> Result<SpaceAddressDirectory, SdkError> {
        self.required(
            Method::GET,
            &format!("{}/addressing", base(space)?),
            None::<&()>,
        )
        .await
    }

    pub async fn issue_space_address(
        &self,
        space: &str,
        request: SpaceAddressIssue,
    ) -> Result<SpaceAddressDirectory, SdkError> {
        self.required(
            Method::POST,
            &format!("{}/addresses", base(space)?),
            Some(&request),
        )
        .await
    }

    pub async fn reserve_space_address(
        &self,
        space: &str,
        installation: &str,
        request: SpaceAddressReservation,
    ) -> Result<SpaceAddressDirectory, SdkError> {
        self.required(
            Method::PUT,
            &format!(
                "{}/reservation",
                resource(space, "addresses", installation)?
            ),
            Some(&request),
        )
        .await
    }

    pub async fn rename_space_address(
        &self,
        space: &str,
        installation: &str,
        request: SpaceAddressRename,
    ) -> Result<SpaceAddressDirectory, SdkError> {
        self.required(
            Method::PUT,
            &format!("{}/name", resource(space, "addresses", installation)?),
            Some(&request),
        )
        .await
    }

    pub async fn revoke_space_address(
        &self,
        space: &str,
        installation: &str,
        request: SpaceAddressRevocation,
    ) -> Result<SpaceAddressDirectory, SdkError> {
        self.required(
            Method::DELETE,
            &resource(space, "addresses", installation)?,
            Some(&request),
        )
        .await
    }
}
