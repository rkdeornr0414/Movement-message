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

    public entry fun initialize_message_box(account: &signer){
        let message_box = MessageBox{
            messages: table::new(),
            message_counter: 0
        };
        move_to(account, message_box);
    }

    public entry fun send_message(account: &signer, recipient: address, content: string::String, timestamp: u64) acquires MessageBox{
        let sender_address = signer::address_of(account);
        assert!(exists<MessageBox>(sender_address), E_NOT_INITIALIZED);

        let message_box = borrow_global_mut<Message>(sender_address);
        let message_id = message_box.message_counter + 1;

        let new_message = Message {
            message_id,
            sender: sender_address,
            recipient,
            content,
            timestamp,
        };

        table::add(&mut message_box.messages, message_id, new_message);
        message_box.message_counter = message_id;
        event::emit(new_message);
    }

    public fun get_received_messages(account: address): vector<Message> acquires MessageBox{
        assert!(exists<MessageBox>(account), E_NOT_INITIALIZED);
        let message_box = borrow_global<MessageBox>(account);
        let received_messages = vector::empty<Message>();

        let length = message_box.message_counter;
        let i = 0;

        loop{
            if( i >= length){
                break
            };
            let message = table::borrow(&message_box.messages, i);
            if(message.recipient == account){
                vector::push_back(&mut received_messages, *message);
            };
            i = i + 1;
        };
        received_messages
    }
}