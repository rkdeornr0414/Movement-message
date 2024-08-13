module move_security_test::young_move {
    use std::signer;
    use std::string;
    use aptos_std::table::{Self, Table};
    use aptos_framework::event;
    use aptos_framework::account;
    use std::vector;

    struct MessageBox has key, store{
        messages: Table<u64, Message>,
        message_counter: u64,
    }

    const E_NOT_INITIALIZED: u64 = 1;

    #[event]
    struct Message has store, drop, copy {
        message_id: u64,
        sender: address,
        recipient: address,
        content: string::String,
        timestamp: u64,
    }
}