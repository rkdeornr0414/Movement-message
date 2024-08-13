module move_security::MovementMessage {
    use std::vector;
    use std::signer;
    use std::option;

    struct Message has key, store, drop {
        id: u64,
        sender: address,
        recipient: address,
        content: vector<u8>,
        timestamp: u64,
    }

    struct MessageBox has key, store {
        messages: vector::T<Message>,
    }

    public fun initialize(owner: &signer) {
        let message_box = MessageBox { messages: vector::empty<Message>() };
        move_to(owner, message_box);
    }

    public fun send_message(sender: &signer, recipient: address, content: vector<u8>, timestamp: u64) {
        let sender_address = signer::address_of(sender);
        let message = Message {
            id: timestamp,
            sender: sender_address,
            recipient,
            content,
            timestamp,
        };
        
        let message_box = borrow_global_mut<MessageBox>(sender_address);
        vector::push_back(&mut message_box.messages, message);
    }

    public fun get_messages(owner: address): vector::T<Message> {
        let message_box = borrow_global<MessageBox>(owner);
        message_box.messages
    }

    public fun get_received_messages(owner: address): vector::T<Message> {
        let message_box = borrow_global<MessageBox>(owner);
        let mut received_messages = vector::empty<Message>();
        let length = vector::length(&message_box.messages);

        let mut i = 0;
        while (i < length) {
            let message = vector::borrow(&message_box.messages, i);
            if (message.recipient == owner) {
                vector::push_back(&mut received_messages, *message);
            }
            i = i + 1;
        }
        received_messages
    }
}
