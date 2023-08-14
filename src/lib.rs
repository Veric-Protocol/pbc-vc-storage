//! pbc-vc-registry

#[macro_use]
extern crate pbc_contract_codegen;

use pbc_contract_common::address::{Address,AddressType};
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
    registry_address: Address,
    vcs: SortedVecMap<String, SortedVecMap<u128, VC>>, // Key: DID, Value: VC Map {Key: VC ID, Value: VC Content}
}

#[init]
fn initialize(
    ctx: ContractContext,
) -> ContractState {

    let vc_storage: SortedVecMap<String, SortedVecMap<u128, VC>> = SortedVecMap::new();
    let blank_address: Address = Address { address_type: AddressType::Account, identifier: [0x00; 20] };
    let state = ContractState {
        owner: ctx.sender,
        registry_address: blank_address,
        vcs: vc_storage,
    };

    state
}

#[derive(ReadWriteRPC, CreateTypeSpec, ReadWriteState)]
pub struct SubjectInfo {
    property_name: String,
    property_value: String,
}

#[derive(ReadWriteRPC, CreateTypeSpec, ReadWriteState)]
pub struct VC {
    valid_since: String,
    valid_until: String,
    subject_did: String,
    subject_info: Vec<SubjectInfo>,
    description: String,
//    content: String,
    revoked: bool,
}

#[action(shortname = 0x01)]
pub fn configure_registry_address(
    context: ContractContext,
    mut state: ContractState,
    target_address: Address,
) -> ContractState {

    assert!(context.sender == state.owner, "Not Authorized!");

    state.registry_address = target_address;

    state
}

#[action(shortname = 0x02)]
pub fn upload_vc(
    context: ContractContext,
    state: ContractState,
    issuer_did: String,
    vc_id: u128,
    subject_did: String,
    subject_info: Vec<SubjectInfo>,
    valid_since: String,
    valid_until: String,
    descrption: String,
    is_revoked: bool,
) -> (ContractState, Vec<EventGroup>) {

    assert!(state.registry_address.identifier != [0x00; 20], "Please configure a valid DID Registry Address!");
    
    let copied_did = issuer_did.clone();
    let mut event_group_builder = EventGroup::builder();
    let new_vc : VC = VC { 
        valid_since: valid_since, 
        valid_until: valid_until, 
        subject_did: subject_did, 
        subject_info: subject_info, 
        description: descrption, 
        revoked: is_revoked, };
    // Call the DID Registry Contract to check if the Sender has the right to upload VC for a certain DID
    // 0x05 is the Shortname for the method implemented on the Registry Contract, needs to be consistent
    event_group_builder
        .call(state.registry_address, Shortname::from_u32(0x05))
        .argument(copied_did)
        .argument(context.sender)
        .done();

    event_group_builder
        .with_callback(SHORTNAME_UPLOAD_VC_CALLBACK)
        .argument(issuer_did)
        .argument(vc_id)
        .argument(new_vc)
        .done();

    (state, vec![event_group_builder.build()])
}

#[callback(shortname = 0x12)]
pub fn upload_vc_callback(
    _context: ContractContext,
    callback_context: CallbackContext,
    mut state: ContractState,
    issuer_did: String,
    vc_id: u128,
    new_vc: VC,
) -> (ContractState, Vec<EventGroup>) {
    assert!(callback_context.success, "DID Not Registered or Not Authorized!");

    if state.vcs.contains_key(&issuer_did) {
        let vcs_map = state.vcs.get_mut(&issuer_did).unwrap();
        assert!(!vcs_map.contains_key(&vc_id), "VC Exists!");
        
        vcs_map.insert(vc_id, new_vc);

    } else {
        let mut vcs_map : SortedVecMap<u128, VC> = SortedVecMap::new();
        vcs_map.insert(vc_id, new_vc);
        state.vcs.insert(issuer_did, vcs_map);
    }

    (state, vec![])
}

#[action(shortname = 0x03)]
pub fn set_revoke(
    context: ContractContext,
    state: ContractState,
    issuer_did: String,
    vc_id: u128,
    is_revoked: bool,
) -> (ContractState, Vec<EventGroup>) {
    
    assert!(state.registry_address.identifier != [0x00; 20], "Please configure a valid DID Registry Address!");

    let copied_did = issuer_did.clone();
    let mut event_group_builder = EventGroup::builder();
    // Call the DID Registry Contract to check if the Sender has the right to upload VC for a certain DID
    // 0x05 is the Shortname for the method implemented on the Registry Contract, needs to be consistent
    event_group_builder
        .call(state.registry_address, Shortname::from_u32(0x05))
        .argument(copied_did)
        .argument(context.sender)
        .done();

    event_group_builder
        .with_callback(SHORTNAME_SET_REVOKE_CALLBACK)
        .argument(issuer_did)
        .argument(vc_id)
        .argument(is_revoked)
        .done();

    (state, vec![event_group_builder.build()])
}

#[callback(shortname = 0x13)]
pub fn set_revoke_callback(
    _context: ContractContext,
    callback_context: CallbackContext,
    mut state: ContractState,
    issuer_did: String,
    vc_id: u128,
    is_revoked: bool,
) -> (ContractState, Vec<EventGroup>) {
    assert!(callback_context.success, "DID Not Registered or Not Authorized!");
    assert!(state.vcs.contains_key(&issuer_did), "VC Not Exist!");

    let vcs_map = state.vcs.get_mut(&issuer_did).unwrap();
    assert!(vcs_map.contains_key(&vc_id), "VC Not Exist!");
    
    vcs_map.get_mut(&vc_id).unwrap().revoked = is_revoked;

    (state, vec![])
}