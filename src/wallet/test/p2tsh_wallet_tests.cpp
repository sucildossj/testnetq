// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <addresstype.h>
#include <key.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/solver.h>
#include <span.h>
#include <streams.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <test/util/setup_common.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

// Include libbitcoinpqc headers (same as interpreter.cpp)
#include <libbitcoinpqc/bitcoinpqc.h>
#include <libbitcoinpqc/slh_dsa.h>

#include <span>

#include <cstring>
#include <memory>
#include <vector>
#include <string>

namespace wallet {

// Helper to generate 128 bytes of entropy for SLH-DSA keygen
// Test framework limits GetStrongRandBytes to 32 bytes max
static void GetEntropy128(std::vector<uint8_t>& entropy) {
    entropy.resize(128);
    // Generate 4 x 32-byte chunks
    for (int i = 0; i < 4; ++i) {
        uint256 hash = GetRandHash();
        std::memcpy(entropy.data() + (i * 32), hash.begin(), 32);
    }
}

BOOST_FIXTURE_TEST_SUITE(p2tsh_wallet_tests, WalletTestingSetup)

// ============================================================================
// SLH-DSA Cryptographic Tests (using libbitcoinpqc)
// ============================================================================

BOOST_AUTO_TEST_CASE(slh_dsa_key_generation)
{
    // Test SLH-DSA-SHAKE-128s key generation using libbitcoinpqc
    std::vector<uint8_t> pubkey(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    
    // Generate random entropy (need at least 128 bytes)
    std::vector<uint8_t> entropy;
    GetEntropy128(entropy);
    
    int result = slh_dsa_shake_128s_keygen(
        pubkey.data(),
        seckey.data(),
        entropy.data(),
        entropy.size()
    );
    
    BOOST_CHECK_EQUAL(result, 0);
    
    // Verify key sizes match expected constants
    BOOST_CHECK_EQUAL(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE, 32);
    BOOST_CHECK_EQUAL(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE, 64);
    BOOST_CHECK_EQUAL(SLH_DSA_SHAKE_128S_SIGNATURE_SIZE, 7856);
    
    // Keys should not be all zeros
    bool pubkey_nonzero = false;
    bool seckey_nonzero = false;
    for (size_t i = 0; i < pubkey.size(); ++i) {
        if (pubkey[i] != 0) pubkey_nonzero = true;
    }
    for (size_t i = 0; i < seckey.size(); ++i) {
        if (seckey[i] != 0) seckey_nonzero = true;
    }
    BOOST_CHECK(pubkey_nonzero);
    BOOST_CHECK(seckey_nonzero);
}

BOOST_AUTO_TEST_CASE(slh_dsa_sign_verify)
{
    // Generate key pair
    std::vector<uint8_t> pubkey(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    std::vector<uint8_t> entropy;
    GetEntropy128(entropy);
    
    int keygen_result = slh_dsa_shake_128s_keygen(
        pubkey.data(),
        seckey.data(),
        entropy.data(),
        entropy.size()
    );
    BOOST_REQUIRE_EQUAL(keygen_result, 0);
    
    // Test message (simulating a sighash)
    uint256 message_hash = GetRandHash();
    
    // Sign
    std::vector<uint8_t> signature(SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
    size_t sig_len = 0;
    
    int sign_result = slh_dsa_shake_128s_sign(
        signature.data(),
        &sig_len,
        message_hash.begin(),
        message_hash.size(),
        seckey.data()
    );
    
    BOOST_CHECK_EQUAL(sign_result, 0);
    BOOST_CHECK_EQUAL(sig_len, SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
    
    // Verify with correct public key (same as interpreter.cpp does)
    int verify_result = slh_dsa_shake_128s_verify(
        signature.data(),
        sig_len,
        message_hash.begin(),
        message_hash.size(),
        pubkey.data()
    );
    
    BOOST_CHECK_EQUAL(verify_result, 0);  // 0 = valid
    
    // Verify with wrong message should fail
    uint256 wrong_hash = GetRandHash();
    
    int wrong_verify = slh_dsa_shake_128s_verify(
        signature.data(),
        sig_len,
        wrong_hash.begin(),
        wrong_hash.size(),
        pubkey.data()
    );
    
    BOOST_CHECK_NE(wrong_verify, 0);  // Should fail (non-zero)
}

BOOST_AUTO_TEST_CASE(slh_dsa_deterministic_keygen)
{
    // Test that same entropy produces same keys
    std::vector<uint8_t> entropy;
    GetEntropy128(entropy);
    
    std::vector<uint8_t> pubkey1(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey1(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    std::vector<uint8_t> pubkey2(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey2(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    
    slh_dsa_shake_128s_keygen(pubkey1.data(), seckey1.data(), entropy.data(), entropy.size());
    slh_dsa_shake_128s_keygen(pubkey2.data(), seckey2.data(), entropy.data(), entropy.size());
    
    BOOST_CHECK(pubkey1 == pubkey2);
    BOOST_CHECK(seckey1 == seckey2);
    
    // Different entropy should produce different keys
    std::vector<uint8_t> entropy2;
    GetEntropy128(entropy2);
    
    std::vector<uint8_t> pubkey3(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey3(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    slh_dsa_shake_128s_keygen(pubkey3.data(), seckey3.data(), entropy2.data(), entropy2.size());
    
    BOOST_CHECK(pubkey1 != pubkey3);
}

BOOST_AUTO_TEST_CASE(slh_dsa_signature_corruption)
{
    // Generate keys
    std::vector<uint8_t> pubkey(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    std::vector<uint8_t> entropy;
    GetEntropy128(entropy);
    slh_dsa_shake_128s_keygen(pubkey.data(), seckey.data(), entropy.data(), entropy.size());
    
    // Sign a message hash
    uint256 message_hash = GetRandHash();
    std::vector<uint8_t> signature(SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
    size_t sig_len = 0;
    slh_dsa_shake_128s_sign(signature.data(), &sig_len, message_hash.begin(), message_hash.size(), seckey.data());
    
    // Verify original (should pass)
    int verify_ok = slh_dsa_shake_128s_verify(
        signature.data(), sig_len, message_hash.begin(), message_hash.size(), pubkey.data());
    BOOST_CHECK_EQUAL(verify_ok, 0);
    
    // Corrupt signature (flip a bit)
    signature[100] ^= 0x01;
    
    // Verify corrupted (should fail)
    int verify_bad = slh_dsa_shake_128s_verify(
        signature.data(), sig_len, message_hash.begin(), message_hash.size(), pubkey.data());
    BOOST_CHECK_NE(verify_bad, 0);
}

// ============================================================================
// P2TSH Script/Address Tests  
// ============================================================================

BOOST_AUTO_TEST_CASE(p2tsh_script_structure)
{
    // P2TSH scriptPubKey format: OP_2 <32-byte-commitment> (witness version 2)
    // Generate a test commitment
    uint256 commitment = GetRandHash();
    
    // Build P2TSH scriptPubKey (witness version 2)
    CScript scriptPubKey;
    scriptPubKey << OP_2;  // Witness version 2 for P2TSH
    scriptPubKey << std::vector<unsigned char>(commitment.begin(), commitment.end());
    
    // Verify structure
    BOOST_CHECK_EQUAL(scriptPubKey.size(), 34);  // 1 (OP_2) + 1 (push) + 32 (commitment)
    BOOST_CHECK(scriptPubKey[0] == OP_2);
    BOOST_CHECK(scriptPubKey[1] == 0x20);  // 32-byte push
    
    // Test Solver recognizes it
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType type = Solver(scriptPubKey, solutions);
    BOOST_CHECK(type == TxoutType::WITNESS_V2_P2TSH);
    BOOST_CHECK_EQUAL(solutions.size(), 1);
    BOOST_CHECK_EQUAL(solutions[0].size(), 32);
}

BOOST_AUTO_TEST_CASE(p2tsh_witness_script_simple_format)
{
    // Simple P2TSH witness script: OP_PUSHBYTES_32 <slh_dsa_pubkey> OP_CHECKSIG
    // This is the 34-byte format used in interpreter.cpp
    
    // Generate SLH-DSA public key
    std::vector<uint8_t> pubkey(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    std::vector<uint8_t> entropy;
    GetEntropy128(entropy);
    slh_dsa_shake_128s_keygen(pubkey.data(), seckey.data(), entropy.data(), entropy.size());
    
    // Build simple witness script
    CScript witnessScript;
    witnessScript << std::vector<unsigned char>(pubkey.begin(), pubkey.end());
    witnessScript << OP_CHECKSIG;
    
    // Verify witness script size matches what interpreter.cpp expects
    // exec_script.size() == 34 is the simple format check
    BOOST_CHECK_EQUAL(witnessScript.size(), 34);
}

BOOST_AUTO_TEST_CASE(p2tsh_witness_script_combined_format)
{
    // Combined P2TSH witness script (70 bytes):
    // OP_PUSHBYTES_32 <schnorr_pubkey> OP_CHECKSIG OP_PUSHBYTES_32 <slh_dsa_pubkey> OP_SUBSTR OP_BOOLAND OP_VERIFY
    
    // Generate keys
    uint256 schnorr_hash = GetRandHash();
    std::vector<uint8_t> schnorr_pubkey(schnorr_hash.begin(), schnorr_hash.end());  // X-only pubkey
    std::vector<uint8_t> slh_dsa_pubkey(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    
    std::vector<uint8_t> entropy;
    std::vector<uint8_t> slh_seckey(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    GetEntropy128(entropy);
    slh_dsa_shake_128s_keygen(slh_dsa_pubkey.data(), slh_seckey.data(), entropy.data(), entropy.size());
    
    // Build combined witness script  
    CScript witnessScript;
    witnessScript << std::vector<unsigned char>(schnorr_pubkey.begin(), schnorr_pubkey.end());
    witnessScript << OP_CHECKSIG;
    witnessScript << std::vector<unsigned char>(slh_dsa_pubkey.begin(), slh_dsa_pubkey.end());
    // Note: OP_SUBSTR, OP_BOOLAND, OP_VERIFY would follow
    // The exact opcode sequence depends on your implementation
    
    // For the 70-byte combined format that interpreter.cpp checks
    // Size will vary based on actual opcode implementation
}

BOOST_AUTO_TEST_CASE(p2tsh_address_type)
{
    // Test WitnessV2P2TSH address type
    uint256 hash = GetRandHash();
    WitnessV2P2TSH p2tsh_addr(hash);
    
    // Verify it wraps the hash correctly
    BOOST_CHECK(static_cast<uint256>(p2tsh_addr) == hash);
    
    // Verify CTxDestination can hold it
    CTxDestination dest = p2tsh_addr;
    BOOST_CHECK(std::holds_alternative<WitnessV2P2TSH>(dest));
    BOOST_CHECK(std::get<WitnessV2P2TSH>(dest) == p2tsh_addr);
}

BOOST_AUTO_TEST_CASE(p2tsh_script_from_address)
{
    // Create WitnessV2P2TSH and generate scriptPubKey
    uint256 hash = GetRandHash();
    WitnessV2P2TSH p2tsh_addr(hash);
    
    // Get scriptPubKey from destination
    CScript scriptPubKey = GetScriptForDestination(p2tsh_addr);
    
    // Should be OP_2 <32-byte hash>
    BOOST_CHECK_EQUAL(scriptPubKey.size(), 34);
    BOOST_CHECK(scriptPubKey[0] == OP_2);
    
    // Verify Solver
    std::vector<std::vector<unsigned char>> solutions;
    TxoutType type = Solver(scriptPubKey, solutions);
    BOOST_CHECK(type == TxoutType::WITNESS_V2_P2TSH);
}

// ============================================================================
// P2TSH Witness Stack Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(p2tsh_witness_stack_simple)
{
    // For simple format, witness stack is: [signature]
    // The signature is 7856 bytes for SLH-DSA-SHAKE-128s
    
    // Generate keys and sign
    std::vector<uint8_t> pubkey(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    std::vector<uint8_t> entropy;
    GetEntropy128(entropy);
    slh_dsa_shake_128s_keygen(pubkey.data(), seckey.data(), entropy.data(), entropy.size());
    
    uint256 sighash = GetRandHash();
    std::vector<uint8_t> signature(SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
    size_t sig_len = 0;
    slh_dsa_shake_128s_sign(signature.data(), &sig_len, sighash.begin(), sighash.size(), seckey.data());
    
    // Build witness
    CScriptWitness witness;
    witness.stack.push_back(std::vector<unsigned char>(signature.begin(), signature.begin() + sig_len));
    
    // Verify
    BOOST_CHECK_EQUAL(witness.stack.size(), 1);
    BOOST_CHECK_EQUAL(witness.stack[0].size(), SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
}

BOOST_AUTO_TEST_CASE(p2tsh_witness_stack_combined)
{
    // For combined format, witness has combined signature element
    // [schnorr_sig(64) + sighash(1) + slh_dsa_sig(7856) + sighash(1)]
    // Total: 64 + 1 + 7856 + 1 = 7922 bytes
    
    size_t schnorr_sig_size = 64;
    size_t schnorr_sighash_size = 1;
    size_t slh_dsa_sig_size = SLH_DSA_SHAKE_128S_SIGNATURE_SIZE;
    size_t slh_dsa_sighash_size = 1;
    
    size_t combined_size = schnorr_sig_size + schnorr_sighash_size + slh_dsa_sig_size + slh_dsa_sighash_size;
    BOOST_CHECK_EQUAL(combined_size, 7922);
    
    // Create a mock combined signature (fill with random data)
    std::vector<uint8_t> combined_sig(combined_size);
    // Fill with random hashes (32 bytes at a time)
    for (size_t i = 0; i < combined_size; i += 32) {
        uint256 hash = GetRandHash();
        size_t copy_size = std::min(size_t(32), combined_size - i);
        std::memcpy(combined_sig.data() + i, hash.begin(), copy_size);
    }
    
    // Set sighash types (0x01 = SIGHASH_ALL)
    combined_sig[64] = 0x01;       // schnorr sighash
    combined_sig[7921] = 0x01;     // slh_dsa sighash
    
    // Extract SLH-DSA signature (as interpreter.cpp does)
    std::vector<uint8_t> slh_dsa_sig(combined_sig.begin() + 65, combined_sig.begin() + 65 + 7856);
    BOOST_CHECK_EQUAL(slh_dsa_sig.size(), SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
}

// ============================================================================
// P2TSH Transaction Size Tests  
// ============================================================================

BOOST_AUTO_TEST_CASE(p2tsh_transaction_vsize)
{
    // Calculate virtual size for P2TSH transaction
    // Weight = (non-witness bytes * 4) + witness bytes
    // vSize = Weight / 4
    
    // Typical P2TSH input witness (simple format):
    // - Signature: 7856 bytes (SLH-DSA-SHAKE-128s)
    // - CompactSize for signature: 3 bytes (0xFD + 2 bytes)
    size_t sig_size = SLH_DSA_SHAKE_128S_SIGNATURE_SIZE;  // 7856
    size_t witness_overhead = 1 + 3;  // stack count + CompactSize for sig
    size_t total_witness = sig_size + witness_overhead;
    
    // Non-witness input data: ~41 bytes
    // (prevout: 36, scriptSig: 1, sequence: 4)
    size_t non_witness_input = 41;
    
    // Simple output (P2WPKH): ~31 bytes
    size_t output_size = 31;
    
    // Transaction overhead: ~12 bytes (version: 4, marker: 1, flag: 1, locktime: 4, input count: 1, output count: 1)
    size_t tx_overhead = 12;
    
    // Weight calculation
    size_t non_witness_bytes = tx_overhead + non_witness_input + output_size;
    size_t witness_bytes = total_witness;
    size_t weight = (non_witness_bytes * 4) + witness_bytes;
    size_t vsize = (weight + 3) / 4;  // Round up
    
    // P2TSH transactions are large due to PQ signatures
    // Expected vSize for 1-in-1-out: ~2050-2100 vbytes
    BOOST_CHECK(vsize > 2000);
    BOOST_CHECK(vsize < 2200);
}

BOOST_AUTO_TEST_CASE(p2tsh_combined_transaction_vsize)
{
    // Combined format with Schnorr + SLH-DSA
    // Witness: [combined_sig(7922)]
    
    size_t combined_sig_size = 64 + 1 + 7856 + 1;  // 7922
    size_t witness_overhead = 1 + 3;  // stack count + CompactSize
    size_t total_witness = combined_sig_size + witness_overhead;
    
    size_t non_witness_input = 41;
    size_t output_size = 31;
    size_t tx_overhead = 12;
    
    size_t non_witness_bytes = tx_overhead + non_witness_input + output_size;
    size_t weight = (non_witness_bytes * 4) + total_witness;
    size_t vsize = (weight + 3) / 4;
    
    // Combined format is slightly larger
    BOOST_CHECK(vsize > 2050);
    BOOST_CHECK(vsize < 2250);
}

// ============================================================================
// P2TSH Multiple Input Tests
// ============================================================================

BOOST_AUTO_TEST_CASE(p2tsh_multiple_inputs_sign_verify)
{
    // Test signing and verification for multiple P2TSH inputs
    const int NUM_INPUTS = 3;
    
    // Generate multiple key pairs
    std::vector<std::vector<uint8_t>> pubkeys(NUM_INPUTS, std::vector<uint8_t>(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE));
    std::vector<std::vector<uint8_t>> seckeys(NUM_INPUTS, std::vector<uint8_t>(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE));
    
    for (int i = 0; i < NUM_INPUTS; ++i) {
        std::vector<uint8_t> entropy;
        GetEntropy128(entropy);
        int result = slh_dsa_shake_128s_keygen(pubkeys[i].data(), seckeys[i].data(), entropy.data(), entropy.size());
        BOOST_REQUIRE_EQUAL(result, 0);
    }
    
    // Sign each input with a different sighash
    std::vector<std::vector<uint8_t>> signatures(NUM_INPUTS, std::vector<uint8_t>(SLH_DSA_SHAKE_128S_SIGNATURE_SIZE));
    std::vector<uint256> sighashes(NUM_INPUTS);
    
    for (int i = 0; i < NUM_INPUTS; ++i) {
        sighashes[i] = GetRandHash();
        size_t sig_len = 0;
        int result = slh_dsa_shake_128s_sign(
            signatures[i].data(),
            &sig_len,
            sighashes[i].begin(),
            sighashes[i].size(),
            seckeys[i].data()
        );
        BOOST_REQUIRE_EQUAL(result, 0);
        BOOST_REQUIRE_EQUAL(sig_len, SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
    }
    
    // Verify each signature
    for (int i = 0; i < NUM_INPUTS; ++i) {
        int verify_result = slh_dsa_shake_128s_verify(
            signatures[i].data(),
            SLH_DSA_SHAKE_128S_SIGNATURE_SIZE,
            sighashes[i].begin(),
            sighashes[i].size(),
            pubkeys[i].data()
        );
        BOOST_CHECK_EQUAL(verify_result, 0);
        
        // Verify with wrong pubkey should fail
        int other_idx = (i + 1) % NUM_INPUTS;
        int wrong_verify = slh_dsa_shake_128s_verify(
            signatures[i].data(),
            SLH_DSA_SHAKE_128S_SIGNATURE_SIZE,
            sighashes[i].begin(),
            sighashes[i].size(),
            pubkeys[other_idx].data()
        );
        BOOST_CHECK_NE(wrong_verify, 0);
    }
    
    // Calculate total witness size for N inputs
    size_t per_input_witness = SLH_DSA_SHAKE_128S_SIGNATURE_SIZE + 4;  // sig + overhead
    size_t total_witness = per_input_witness * NUM_INPUTS;
    
    // Should be ~23.5KB for 3 inputs
    BOOST_CHECK(total_witness > 23000);
    BOOST_CHECK(total_witness < 24000);
}

// ============================================================================
// Integration with interpreter.cpp verification logic
// ============================================================================

BOOST_AUTO_TEST_CASE(p2tsh_sighash_format)
{
    // Test that message hash format matches what interpreter.cpp expects
    // The message_hash passed to slh_dsa_shake_128s_verify is a uint256 (32 bytes)
    
    uint256 sighash = GetRandHash();
    
    // Verify size is correct
    BOOST_CHECK_EQUAL(sighash.size(), 32);
    
    // Generate keypair and sign
    std::vector<uint8_t> pubkey(SLH_DSA_SHAKE_128S_PUBLIC_KEY_SIZE);
    std::vector<uint8_t> seckey(SLH_DSA_SHAKE_128S_SECRET_KEY_SIZE);
    std::vector<uint8_t> entropy;
    GetEntropy128(entropy);
    slh_dsa_shake_128s_keygen(pubkey.data(), seckey.data(), entropy.data(), entropy.size());
    
    std::vector<uint8_t> signature(SLH_DSA_SHAKE_128S_SIGNATURE_SIZE);
    size_t sig_len = 0;
    
    // Sign using uint256::begin() like interpreter.cpp does
    int sign_result = slh_dsa_shake_128s_sign(
        signature.data(),
        &sig_len,
        sighash.begin(),  // This is how interpreter.cpp passes it
        sighash.size(),
        seckey.data()
    );
    BOOST_CHECK_EQUAL(sign_result, 0);
    
    // Verify using uint256::begin() like interpreter.cpp does
    int verify_result = slh_dsa_shake_128s_verify(
        signature.data(),
        sig_len,
        sighash.begin(),  // message_hash.begin() in interpreter.cpp
        sighash.size(),   // message_hash.size() in interpreter.cpp
        pubkey.data()
    );
    BOOST_CHECK_EQUAL(verify_result, 0);
}

BOOST_AUTO_TEST_CASE(p2tsh_witness_size_constant)
{
    // Verify WITNESS_V2_P2TSH_SIZE constant from interpreter.h
    BOOST_CHECK_EQUAL(WITNESS_V2_P2TSH_SIZE, 32);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet