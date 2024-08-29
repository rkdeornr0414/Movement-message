module move_security_test::user_messaging {
    use std::signer;
    use std::string;
    use aptos_std::table::{Self, Table};
    use aptos_framework::event;

    // Define the structure for user data
    struct User has key, store {
        address: address,
        username: string::String,
    }

    // Define the structure for storing all users
    struct UserRegistry has key, store {
        users: Table<address, User>,
        user_counter: u64,
    }

    // Define a structure for messages
    struct Message has store, drop, copy {
        message_id: u64,
        sender: address,
        recipient: address,
        content: string::String,
        timestamp: u64,
    }

    const E_NOT_INITIALIZED: u64 = 1;
    const E_USER_ALREADY_EXISTS: u64 = 2;

    #[event]
    struct UserRegistered has store, drop, copy {
        address: address,
        username: string::String,
    }

    // Initialize user registry
    public entry fun initialize_user_registry(account: &signer) {
        let user_registry = UserRegistry {
            users: table::new(),
            user_counter: 0,
        };
        move_to(account, user_registry);
    }

    // Register a new user
    public entry fun register_user(account: &signer, username: string::String) acquires UserRegistry {
        let account_address = signer::address_of(account);
        assert!(!exists<UserRegistry>(account_address), E_NOT_INITIALIZED);

        let user_registry = borrow_global_mut<UserRegistry>(account_address);
        let user = User {
            address: account_address,
            username,
        };

        assert!(table::contains(&user_registry.users, account_address) == false, E_USER_ALREADY_EXISTS);

        table::add(&mut user_registry.users, account_address, user);
        user_registry.user_counter = user_registry.user_counter + 1;

        let user_registered_event = UserRegistered {
            address: account_address,
            username,
        };
        event::emit(user_registered_event);
    }

    // Function to retrieve a username by address
    public fun get_username(account: address): string::String acquires UserRegistry {
        let user_registry = borrow_global<UserRegistry>(account);
        let user = table::borrow(&user_registry.users, account);
        user.username
    }
}

