#include "../shell/Dispatcher.h"
#include <crypto-encode/hex.h>
#include <crypto-bn/bn.h>
#include <string>
#include <vector>
#include <utility>
#include <stdlib.h>
#include <unistd.h>
#include <cstring>
#include <sstream>

using safeheron::bignum::BN;

class EncryptTextTask: public Task
{
public:
    /**
     * @brief : The execution of signature combination tasks.
     * @param request_id[in] : The unique ID of each request.
     * @param request[in] : The request body, JSON string.
     * @param reply[out] : The combined signature result, JSON string.
     * @param error_msg[out] : An error message is returned when the execution is failed.
     * @return int : return 0 if success, otherwise return an error code.
     */
    virtual int execute(const std::string &request_id, const std::string &request, std::string &reply, std::string &error_msg);

    /**
     * @brief : Get the current task type.
     * @return int : Return the task type number defined in TaskConstant.h
     */
    virtual int get_task_type();

private:
    /**
     * @brief : Construct a JSON string after the signature combination is done.
     * @param request_id[in] : The unique ID of each request.
     * @param encrypted_aes_key[in] : The encrypted AES key.
     * @param encrypted_text[in] : The encrypted text.
     * @param out_str[out] : A JSON string that represents the combination result.
     *                       The JSON structure is shown as below.
     *   {
     *     "success": true,
     *     "encrypted_aes_key": "base64 encoded encrypted AES key",
     *     "encrypted_text": "base64 encoded encrypted text"
     *   }
     *
     * @return int : Return 0 if success, otherwise return an error code.
     */
    int get_reply_string(const std::string &request_id, const std::string &encrypted_aes_key, const std::string &encrypted_text, std::string &out_str);

    BN compute_shared_secret(const BN &private_key, const std::vector<uint8_t> &remote_pubkey_bytes);
    std::vector<uint8_t>    encrypt_with_aes_key(const std::vector<uint8_t> &key, const std::vector<uint8_t> &plaintext);
    /**
     * @brief : Perform ECDH and encrypt the plaintext.
     * @param local_private_key[in] : The local private key.
     * @param plaintext[in] : The plaintext to be encrypted.
     * @param remote_pubkey_hex[in] : The remote public key in hex format.
     * @return std::pair<std::string, std::string> : A pair containing the base64 encoded encrypted AES key and encrypted text.
     */
    std::pair<std::string, std::string> perform_ecdh_and_encrypt(const BN &local_private_key, const std::string &plaintext, const std::string &remote_pubkey_hex);

    std::string derive_sha256_hash(const std::string &request_id, const std::string &timestamp);
    bool verify_signature(const std::string &msg_digest, const std::string &signature, const std::string &remote_public_key_hex);
    std::string decrypt_with_aes_key(const std::vector<uint8_t> &key, const std::vector<uint8_t> &ciphertext);
};