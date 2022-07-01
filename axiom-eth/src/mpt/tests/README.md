Here is some useful information regarding the mpt_tests

With 500 keys, it is sufficient to use the parameters max_depth = 6 and max_key_byte_len = 3.

loose - in these tests, we use max_depth = 6 and max_key_byte_len = 32, key_byte_len = Some(key.len()) 
tight - in these tests, we use max_depth = proof.len() + slot_is_empty, max_key_byte_len = key.len(), key_byte_len = Some(key.len()) 
fixed - in these tests, we use max_depth = 6, max_key_byte_len = key.len(), key_byte_len = None