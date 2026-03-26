use monad_crypto::certificate_signature::PubKey;
use monad_types::Round;

use crate::{
    udp::ValidatedChunk,
    util::{BroadcastMode, BuildTarget, PrimaryBroadcastGroup},
};

// Gradual rollout from v0 (regular) to v1 (deterministic) raptorcast.
//
// The rollout proceeds through four stages, bumped on release:
//
//                    AcceptBoth        AcceptBoth
//   AlwaysV0         PublishV0         PublishV1          AlwaysV1
//  -----------------+------------------+------------------+----------
//   v0 only         |  accept both,    |  accept both,    |  v1 only
//                   |  publish v0      |  publish v1      |

pub const CURRENT_STAGE: DeterministicProtocolRolloutStage =
    DeterministicProtocolRolloutStage::AlwaysV1;

#[derive(Debug, Clone, Copy)]
pub enum DeterministicProtocolRolloutStage {
    AlwaysV0,
    AcceptBothPublishV0,
    AcceptBothPublishV1,
    AlwaysV1,
}

impl DeterministicProtocolRolloutStage {
    // should only be called on receiving a v0 or v1 primary raptorcast chunk
    pub(crate) fn should_accept<PT: PubKey>(&self, chunk: &ValidatedChunk<PT>) -> bool {
        match chunk.broadcast_mode {
            BroadcastMode::DeterministicPrimary(_) => self.should_accept_v1(),
            BroadcastMode::Primary => self.should_accept_v0(),
            _ => panic!("should_accept called on non-primary raptorcast chunk"),
        }
    }

    // should only be called when building primary raptorcast message
    pub(crate) fn build_target<'a, PT: PubKey>(
        &self,
        message_round: Round,
        group: PrimaryBroadcastGroup<'a, PT>,
    ) -> BuildTarget<'a, PT> {
        if self.should_publish_v1() {
            BuildTarget::deterministic_raptorcast(group, message_round)
        } else {
            BuildTarget::raptorcast(group)
        }
    }

    fn should_accept_v0(&self) -> bool {
        !matches!(self, Self::AlwaysV1)
    }

    #[expect(unused)]
    fn should_publish_v0(&self) -> bool {
        matches!(self, Self::AlwaysV0 | Self::AcceptBothPublishV0)
    }

    fn should_accept_v1(&self) -> bool {
        !matches!(self, Self::AlwaysV0)
    }

    fn should_publish_v1(&self) -> bool {
        matches!(self, Self::AcceptBothPublishV1 | Self::AlwaysV1)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use bytes::Bytes;
    use itertools::Itertools as _;
    use monad_crypto::{
        certificate_signature::CertificateSignaturePubKey,
        hasher::{Hasher, HasherType},
    };
    use monad_secp::{KeyPair, SecpSignature};
    use monad_types::{Epoch, NodeId, Round, Stake};
    use monad_validator::validator_set::{ValidatorSet, ValidatorSetType as _};

    use super::DeterministicProtocolRolloutStage;
    use crate::{
        auth::AuthRecvMsg,
        packet::MessageBuilder,
        udp::UdpState,
        util::{FullNodeGroupMap, PrimaryBroadcastGroup, Redundancy},
    };

    type SignatureType = SecpSignature;
    type PubKeyType = CertificateSignaturePubKey<SignatureType>;

    const EPOCH: Epoch = Epoch(5);
    const ROUND: Round = Round(42);

    fn make_key_pair(n: u8) -> KeyPair {
        let mut hasher = HasherType::new();
        hasher.update(n.to_le_bytes());
        let mut hash = hasher.hash();
        KeyPair::from_bytes(&mut hash.0).unwrap()
    }

    fn validator_set() -> (KeyPair, ValidatorSet<PubKeyType>) {
        let mut keys = (0_u8..100).map(make_key_pair).collect_vec();
        let valset = keys
            .iter()
            .map(|key| (NodeId::new(key.pubkey()), Stake::ONE))
            .collect();
        let validators = ValidatorSet::new_unchecked(valset);
        (keys.pop().unwrap(), validators)
    }

    // returns the number of successfully decoded messages.
    fn rollout_publish_and_receive(
        publisher_stage: DeterministicProtocolRolloutStage,
        receiver_stage: DeterministicProtocolRolloutStage,
    ) -> usize {
        let (sender_key, validators) = validator_set();
        let sender_id = NodeId::new(sender_key.pubkey());
        let group_map = [(EPOCH, validators.clone())].into();
        let fn_group_map = FullNodeGroupMap::default();
        let group = PrimaryBroadcastGroup::of_epoch(EPOCH, &sender_id, &group_map).unwrap();

        let app_message: Bytes = vec![0xAB_u8; 64 * 1024].into();

        // Build packets using the publisher's rollout stage
        let build_target = publisher_stage.build_target(ROUND, group);
        let packets = MessageBuilder::<SignatureType>::new(&sender_key)
            .redundancy(Redundancy::from_u8(2))
            .build_vec(&app_message, &build_target)
            .expect("build should succeed");
        assert!(!packets.is_empty());

        // Set up receiver
        let receiver_id = validators
            .get_members()
            .keys()
            .find(|id| **id != sender_id)
            .copied()
            .unwrap();

        let mut udp_state = UdpState::<SignatureType>::new(receiver_id, u64::MAX, 10_000);
        udp_state.set_v1_rollout(receiver_stage);

        // Feed all packets into the receiver
        let mut decoded_count = 0;
        for packet in &packets {
            let recv_msg = AuthRecvMsg {
                src_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8000),
                payload: packet.payload.clone(),
                stride: packet.stride as u16,
                sender: None,
            };
            let decoded =
                udp_state.handle_message(&group_map, &fn_group_map, |_, _, _| {}, recv_msg);
            decoded_count += decoded.len();
        }

        decoded_count
    }

    #[test]
    fn test_rollout_adjacent_stages_compatible() {
        use DeterministicProtocolRolloutStage::*;
        let stages = [AlwaysV0, AcceptBothPublishV0, AcceptBothPublishV1, AlwaysV1];

        for window in stages.windows(2) {
            let (a, b) = (window[0], window[1]);
            let count = rollout_publish_and_receive(a, b);
            assert_eq!(count, 1);

            let count = rollout_publish_and_receive(b, a);
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn test_rollout_non_adjacent_stages_incompatible() {
        use DeterministicProtocolRolloutStage::{self as Stage, *};

        const NON_ADJACENT_PAIRS: &[(Stage, Stage)] = &[
            (AlwaysV0, AcceptBothPublishV1),
            (AcceptBothPublishV0, AlwaysV1),
            (AlwaysV0, AlwaysV1),
        ];

        for (a, b) in NON_ADJACENT_PAIRS {
            let count1 = rollout_publish_and_receive(*a, *b);
            let count2 = rollout_publish_and_receive(*b, *a);
            assert!(count1 == 0 || count2 == 0);
        }
    }
}
