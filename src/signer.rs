use crate::error::{Result, TurnkeyError};
use alloy_consensus::SignableTransaction;
use alloy_network::{
    AnyNetwork, AnyTxEnvelope, AnyTypedTransaction, Ethereum, Network, NetworkWallet,
};
use alloy_primitives::{Address, ChainId, Signature, B256, U256};
use alloy_signer::Signer;
use std::sync::Arc;
use turnkey_client::generated::immutable::activity::v1::SignRawPayloadIntentV2;
use turnkey_client::generated::immutable::common::v1::{HashFunction, PayloadEncoding};
use turnkey_client::{TurnkeyClient, TurnkeyP256ApiKey};

#[derive(Clone, Debug)]
pub struct TurnkeySigner {
    client: Arc<TurnkeyClient<TurnkeyP256ApiKey>>,
    organization_id: String,
    address: Address,
    chain_id: Option<ChainId>,
}

impl TurnkeySigner {
    /// Create a new Turnkey signer
    pub fn new(
        organization_id: String,
        address: Address,
        api_key: TurnkeyP256ApiKey,
    ) -> Result<Self> {
        let client = TurnkeyClient::builder()
            .api_key(api_key)
            .build()
            .map_err(|e| TurnkeyError::Configuration(e.to_string()))?;

        Ok(Self {
            client: Arc::new(client),
            organization_id,
            address,
            chain_id: None,
        })
    }

    /// Set the chain ID for this signer
    pub fn with_chain_id(mut self, chain_id: Option<ChainId>) -> Self {
        self.chain_id = chain_id;
        self
    }
}

#[async_trait::async_trait]
impl Signer<Signature> for TurnkeySigner {
    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }

    async fn sign_hash(&self, hash: &B256) -> std::result::Result<Signature, alloy_signer::Error> {
        let payload = hex::encode(hash.as_slice());

        let intent = SignRawPayloadIntentV2 {
            sign_with: self.address.to_string(),
            payload,
            encoding: PayloadEncoding::Hexadecimal,
            hash_function: HashFunction::NoOp,
        };

        let response = self
            .client
            .sign_raw_payload(
                self.organization_id.clone(),
                self.client.current_timestamp(),
                intent,
            )
            .await
            .map_err(|e| alloy_signer::Error::other(format!("Turnkey API error: {e}")))?;

        // Parse signature components
        let r_bytes = hex::decode(&response.r)
            .map_err(|e| alloy_signer::Error::other(format!("Invalid r: {e}")))?;
        let s_bytes = hex::decode(&response.s)
            .map_err(|e| alloy_signer::Error::other(format!("Invalid s: {e}")))?;
        let v: u64 = response
            .v
            .parse()
            .map_err(|e| alloy_signer::Error::other(format!("Invalid v: {e}")))?;

        let r = U256::from_be_slice(&r_bytes);
        let s = U256::from_be_slice(&s_bytes);

        let parity = match v {
            27 => false,
            28 => true,
            0 => false,
            1 => true,
            _ => {
                if let Some(chain_id) = self.chain_id {
                    let expected_base = chain_id * 2 + 35;
                    match v {
                        v if v == expected_base => false,
                        v if v == expected_base + 1 => true,
                        _ => {
                            return Err(alloy_signer::Error::other(format!(
                                "Invalid v value for chain {chain_id}: {v}"
                            )))
                        }
                    }
                } else {
                    return Err(alloy_signer::Error::other(format!("Invalid v value: {v}")));
                }
            }
        };

        Ok(Signature::new(r, s, parity))
    }

    fn with_chain_id(self, chain_id: Option<ChainId>) -> Self {
        Self::with_chain_id(self, chain_id)
    }
}

impl NetworkWallet<AnyNetwork> for TurnkeySigner {
    fn default_signer_address(&self) -> Address {
        self.address
    }

    fn has_signer_for(&self, address: &Address) -> bool {
        self.address == *address
    }

    fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        std::iter::once(self.address)
    }

    async fn sign_transaction_from(
        &self,
        sender: Address,
        tx: <AnyNetwork as Network>::UnsignedTx,
    ) -> alloy_signer::Result<<AnyNetwork as Network>::TxEnvelope> {
        if sender != self.address {
            return Err(alloy_signer::Error::other(format!(
                "Sender address {sender} does not match signer address {}",
                self.address
            )));
        }

        // Match on the transaction type and handle each variant
        match tx {
            AnyTypedTransaction::Ethereum(mut eth_tx) => {
                // Set chain ID if configured
                if let Some(chain_id) = self.chain_id {
                    eth_tx.set_chain_id(chain_id);
                }

                // Get the signature hash and sign it
                let signature_hash = eth_tx.signature_hash();
                let signature = self.sign_hash(&signature_hash).await?;

                // Convert to signed envelope
                Ok(AnyTxEnvelope::Ethereum(
                    eth_tx.into_signed(signature).into(),
                ))
            }
            _ => Err(alloy_signer::Error::other(
                "Cannot sign unknown transaction type",
            )),
        }
    }
}

impl NetworkWallet<Ethereum> for TurnkeySigner {
    fn default_signer_address(&self) -> Address {
        self.address
    }

    fn has_signer_for(&self, address: &Address) -> bool {
        self.address == *address
    }

    fn signer_addresses(&self) -> impl Iterator<Item = Address> {
        std::iter::once(self.address)
    }

    async fn sign_transaction_from(
        &self,
        sender: Address,
        mut tx: <Ethereum as Network>::UnsignedTx,
    ) -> alloy_signer::Result<<Ethereum as Network>::TxEnvelope> {
        if sender != self.address {
            return Err(alloy_signer::Error::other(format!(
                "Sender address {sender} does not match signer address {}",
                self.address
            )));
        }

        // Set chain ID if configured
        if let Some(chain_id) = self.chain_id {
            tx.set_chain_id(chain_id);
        }

        // Get the signature hash and sign it
        let signature_hash = tx.signature_hash();
        let signature = self.sign_hash(&signature_hash).await?;

        // Convert to signed envelope
        Ok(tx.into_signed(signature).into())
    }
}
