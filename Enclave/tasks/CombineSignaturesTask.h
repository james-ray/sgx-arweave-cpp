/**
 * @file CombineSignatures.h
 * @brief : CombineSignatures.h contains the execution of signature combination requests. The process has 3 steps.
 *          Firstly, the document and signature shares are parsed from the request body.
 *          Then, Safeheron's API is called to combine the signature shares into a single signature.
 *          Finally, the result is packed into a JSON structure and returned.
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "../shell/Dispatcher.h"
#include <crypto-tss-rsa/tss_rsa.h>
#include <crypto-tss-rsa/RSASigShare.h>
#include <crypto-tss-rsa/RSAPublicKey.h>
#include <crypto-tss-rsa/RSAKeyMeta.h>
#include <crypto-encode/hex.h>
#include <string>
#include <vector>

using safeheron::tss_rsa::RSASigShare;
using safeheron::tss_rsa::RSAPublicKey;
using safeheron::tss_rsa::RSAKeyMeta;

class CombineSignaturesTask: public Task
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
    virtual int execute( const std::string & request_id, const std::string & request, std::string & reply, std::string & error_msg );

    /**
     * @brief : Get the current task type.
     * @return int : Return the task type number defined in TaskConstant.h
     */
    virtual int get_task_type( );

private:
    /**
     * @brief : Construct a JSON string after the signature combination is done.
     * @param request_id[in] : The unique ID of each request.
     * @param out_sig[in] : The combined signature.
     * @param out_str[out] : A JSON string that represents the combination result.
     *                       The JSON structure is shown as below.
     *   {
     *     "success": true,
     *     "signature": "combined signature hex string"
     *   }
     *
     * @return int : Return TEE_OK if success, otherwise return an error code.
     */
    int get_reply_string( const std::string & request_id, const safeheron::bignum::BN & out_sig, std::string & out_str );
};