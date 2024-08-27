module move_security_test::user_registration {
    use std::signer;
    use std::string;
    use aptos_std::table::{Self, Table};
    use aptos_framework::event;
    use std::vector;

    struct User has key, store {
        address: address,
        username: string::String,
    }

    struct UserRegistry has key, store {
        users: Table<address, User>,
        user_counter: u64,
    }

    struct Message has store, drop, copy {
        sender: address,
        recipient: address,
        content: string::String,
    }

    struct MessageRegistry has key, store {
        messages: Table<u64, Message>,
        message_counter: u64,
    }

    const E_NOT_INITIALIZED: u64 = 1;
    const E_USER_ALREADY_EXISTS: u64 = 2;
    const E_NO_MESSAGE_REGISTRY: u64 = 3;

    #[event]
    struct UserRegistered has store, drop, copy {
        address: address,
        username: string::String,
    }

    #[event]
    struct MessageSent has store, drop, copy {
        sender: address,
        recipient: address,
        content: string::String,
    }

    public entry fun initialize_user_registry(account: &signer) {
        let user_registry = UserRegistry {
            users: table::new(),
            user_counter: 0
        };
        move_to(account, user_registry);

        let message_registry = MessageRegistry {
            messages: table::new(),
            message_counter: 0
        };
        move_to(account, message_registry);
    }

    public entry fun register_user(account: &signer, username: string::String) acquires UserRegistry {
        let account_address = signer::address_of(account);
        assert!(!exists<UserRegistry>(account_address), E_NOT_INITIALIZED);

        let user_registry = borrow_global_mut<UserRegistry>(account_address);
        let user = User {
            address: account_address,
            username: username,
        };

        assert!(table::contains_key(&user_registry.users, account_address) == false, E_USER_ALREADY_EXISTS);

        table::add(&mut user_registry.users, account_address, user);
        user_registry.user_counter = user_registry.user_counter + 1;

        let user_registered_event = UserRegistered {
            address: account_address,
            username: username,
        };
        event::emit(user_registered_event);
    }

    public entry fun send_message(account: &signer, recipient: address, content: string::String) acquires MessageRegistry {
        let sender_address = signer::address_of(account);
        assert!(exists<MessageRegistry>(sender_address), E_NO_MESSAGE_REGISTRY);

        let message_registry = borrow_global_mut<MessageRegistry>(sender_address);
        let message_id = message_registry.message_counter;

        let message = Message {
            sender: sender_address,
            recipient: recipient,
            content: content,
        };

        table::add(&mut message_registry.messages, message_id, message);
        message_registry.message_counter = message_id + 1;

        let message_sent_event = MessageSent {
            sender: sender_address,
            recipient: recipient,
            content: content,
        };
        event::emit(message_sent_event);
    }

    public fun get_messages(account: address): vector<Message> acquires MessageRegistry {
        let message_registry = borrow_global<MessageRegistry>(account);
        let all_messages = vector::empty<Message>();

        let counter = message_registry.message_counter;
        let i = 0;

        loop {
            if (i >= counter) {
                break;
            };
            let message = table::borrow(&message_registry.messages, i);
            vector::push_back(&mut all_messages, *message);
            i = i + 1;
        };
        all_messages
    }

    public fun get_username(account: &signer, user_address: address): string::String acquires UserRegistry {
        let account_address = signer::address_of(account);
        let user_registry = borrow_global<UserRegistry>(account_address);
        let user = table::borrow(&user_registry.users, user_address);
        user.username
    }
}
