//! pbc-vc-storage

#[macro_use]
extern crate pbc_contract_codegen;

use core::panic;

use pbc_contract_common::address::Address;
use pbc_contract_common::context::{ContractContext, CallbackContext};
use pbc_contract_common::events::EventGroup;
use pbc_contract_common::shortname::Shortname;
use pbc_contract_common::sorted_vec_map::SortedVecMap;
use read_write_state_derive::ReadWriteState;
use read_write_rpc_derive::ReadWriteRPC;
use create_type_spec_derive::CreateTypeSpec;


#[state]
pub struct ContractState {
    owner: Address,
    vcs: SortedVecMap<String, SortedVecMap<u128, VC>>, // Key: DID, Value: VC Map {Key: VC ID, Value: VC Content}
}

#[init]
fn initialize(
    ctx: ContractContext,
) -> ContractState {

    let vc_storage: SortedVecMap<String, SortedVecMap<u128, VC>> = SortedVecMap::new();

    let state = ContractState {
        owner: ctx.sender,
        vcs: vc_storage,
    };

    state
}

#[derive(ReadWriteRPC, CreateTypeSpec, ReadWriteState)]
pub struct VC {
    content: String,
    revoked: bool,
}

#[action(shortname = 0x01)]
pub fn upload_vc(
    context: ContractContext,
    state: ContractState,
    registry_address: Address,
    did: String,
    vc_id: u128,
    vc_json: String,
    is_revoked: bool,
) -> (ContractState, Vec<EventGroup>) {
    
    let copied_did = did.clone();
    let mut event_group_builder = EventGroup::builder();
    // Call the DID Registry Contract to check if the Sender has the right to upload VC for a certain DID
    // 0x05 is the Shortname for the method implemented on the Registry Contract, needs to be consistent
    event_group_builder
        .call(registry_address, Shortname::from_u32(0x05))
        .argument(copied_did)
        .argument(context.sender)
        .done();

    event_group_builder
        .with_callback(SHORTNAME_UPLOAD_VC_CALLBACK)
        .argument(did)
        .argument(vc_id)
        .argument(vc_json)
        .argument(is_revoked)
        .done();

    (state, vec![event_group_builder.build()])
}

#[callback(shortname = 0x11)]
pub fn upload_vc_callback(
    _context: ContractContext,
    callback_context: CallbackContext,
    mut state: ContractState,
    did: String,
    vc_id: u128,
    vc_json: String,
    is_revoked: bool,
) -> (ContractState, Vec<EventGroup>) {
    assert!(callback_context.success, "DID Not Registered or Not Authorized!");

    let new_vc: VC = VC {
        content: vc_json,
        revoked: is_revoked,
    };
    if state.vcs.contains_key(&did) {
        let vcs_map = state.vcs.get_mut(&did).unwrap();
        if vcs_map.contains_key(&vc_id) {
            panic!("VC Exists!")
        }
        vcs_map.insert(vc_id, new_vc);

    } else {
        let mut vcs_map : SortedVecMap<u128, VC> = SortedVecMap::new();
        vcs_map.insert(vc_id, new_vc);
        state.vcs.insert(did, vcs_map);
    }

    (state, vec![])
}

#[action(shortname = 0x02)]
pub fn set_revoke(
    context: ContractContext,
    state: ContractState,
    registry_address: Address,
    did: String,
    vc_id: u128,
    is_revoked: bool,
) -> (ContractState, Vec<EventGroup>) {
    
    let copied_did = did.clone();
    let mut event_group_builder = EventGroup::builder();
    // Call the DID Registry Contract to check if the Sender has the right to upload VC for a certain DID
    // 0x05 is the Shortname for the method implemented on the Registry Contract, needs to be consistent
    event_group_builder
        .call(registry_address, Shortname::from_u32(0x05))
        .argument(copied_did)
        .argument(context.sender)
        .done();

    event_group_builder
        .with_callback(SHORTNAME_SET_REVOKE_CALLBACK)
        .argument(did)
        .argument(vc_id)
        .argument(is_revoked)
        .done();

    (state, vec![event_group_builder.build()])
}

#[callback(shortname = 0x12)]
pub fn set_revoke_callback(
    _context: ContractContext,
    callback_context: CallbackContext,
    mut state: ContractState,
    did: String,
    vc_id: u128,
    is_revoked: bool,
) -> (ContractState, Vec<EventGroup>) {
    assert!(callback_context.success, "DID Not Registered or Not Authorized!");

    if state.vcs.contains_key(&did) {
        let vcs_map = state.vcs.get_mut(&did).unwrap();
        if vcs_map.contains_key(&vc_id) {
            vcs_map.get_mut(&vc_id).unwrap().revoked = is_revoked;
        } else {
            panic!("VC Not Exist!")
        }

    } else {
       panic!("VC Not Exist!")
    }

    (state, vec![])
}