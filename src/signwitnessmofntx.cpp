#include <CoinCore/hash.h>
#include <CoinCore/numericdata.h>
#include <CoinCore/secp256k1_openssl.h>

#include <CoinQ/CoinQ_script.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>

using namespace Coin;
using namespace CoinCrypto;
using namespace CoinQ::Script;

using namespace std;

int main(int argc, char* argv[])
{
    if (argc < 4 || argc > 5)
    {
        cerr << "# Usage: " << argv[0] << " <rawtx> <outpoint amount> <privkey> [verbose = 0]" << endl;
        return -1;
    }

    try
    {
        bool verbose = (argc > 4 ? (strtoul(argv[4], NULL, 0) != 0) : false);

        uchar_vector rawtx(argv[1]);
        Transaction tx(rawtx);
        if (tx.inputs.size() != 1)
            throw runtime_error("Invalid transaction type 1.");

        if (tx.witness.txinwits.size() != 1)
            throw runtime_error("Invalid transaction type 2.");

        std::vector<uchar_vector>& stack = tx.witness.txinwits[0].scriptWitness.stack;
        if (stack.size() == 0)
            throw runtime_error("Invalid witness type.");

        uchar_vector redeemscript = stack.back();
        if (redeemscript.size() < 35)
            throw runtime_error("Invalid redeemscript 1.");

        if (redeemscript.back() != OP_CHECKMULTISIG)
            throw runtime_error("Invalis redeemscript 2.");

        uchar_vector witnessscript;
        witnessscript << OP_1 << pushStackItem(sha256(redeemscript));

        if (tx.inputs[0].scriptSig != pushStackItem(witnessscript))
            throw runtime_error("Invalid scriptSig.");

        uint pos = 0;
        int minsigs = redeemscript[pos++] - OP_1_OFFSET;
        if (minsigs < 0 || minsigs > 15)
            throw runtime_error("Invalid minsigs.");

        if ((int)stack.size() - 1 > minsigs)
            throw runtime_error("Too many signatures.");

        vector<uchar_vector> pubkeys;
        while (pos < redeemscript.size() - 2)
        {
            int len = getDataLength(redeemscript, pos);
            if (redeemscript.size() < pos + len)
                throw runtime_error("Invalid redeemscript 3.");

            uchar_vector pubkey(redeemscript.begin() + pos, redeemscript.begin() + pos + len); pos += len;
            pubkeys.push_back(pubkey);
        }
        if (pos != redeemscript.size() - 2)
            throw runtime_error("Invalid redeemscript 4.");

        if ((int)pubkeys.size() != (int)redeemscript[pos] - OP_1_OFFSET)
            throw runtime_error("Invalid redeemscript 5.");

        sort(pubkeys.begin(), pubkeys.end());

        uint64_t outpointamount = strtoull(argv[2], NULL, 0);
        uchar_vector privkey(argv[3]);
        if (privkey.size() != 32) throw runtime_error("Invalid private key length.");

        secp256k1_key signingKey;
        signingKey.setPrivKey(privkey);
        uchar_vector pubkey = signingKey.getPubKey();

        int sigindex = 0;
        for (; sigindex < (int)pubkeys.size(); sigindex++)
        {
            if (pubkeys[sigindex] == pubkey) break;
        }
        if (sigindex == pubkeys.size())
            throw runtime_error("No matching pubkey for privkey.");

        if (verbose) cout << "sigindex: " << sigindex << endl;

        uchar_vector signingHash = tx.getSigHash(Coin::SIGHASH_ALL, 0, redeemscript, outpointamount);
        int nextsig = 0;
        bool didSign = false;
        vector<uchar_vector> newStack;
        if (stack.size() == 1)
        {
            if (verbose) cout << "signing." << endl;
            uchar_vector sig = secp256k1_sign_rfc6979(signingKey, signingHash);
            sig.push_back(Coin::SIGHASH_ALL);
            newStack.push_back(sig);
            didSign = true;
        }

        for (int i = 0; i < (int)stack.size() - 1; i++)
        {
            if (stack[i].empty())
                throw runtime_error("Invalid signature.");

            if (stack[i].back() != Coin::SIGHASH_ALL)
                throw runtime_error("Unsupported sighash type.");

            uchar_vector sig(stack[i].begin(), stack[i].end() - 1);

            int j = nextsig;
            for (; j < (int)pubkeys.size(); j++)
            {
                uchar_vector verifiedSig;
                secp256k1_key verificationKey;
                verificationKey.setPubKey(pubkeys[j]);
                if (verbose) cout << "verificationKey: " << pubkeys[j].getHex() << endl;

                bool verified = secp256k1_verify(verificationKey, signingHash, sig);
                if (verified)
                {
                    if (verbose) cout << "verify succeeded. stack: " << i << "   pubkey: " << j << endl; 
                    if (sigindex == j)
                        throw runtime_error("Already signed with this privkey.");

                    newStack.push_back(stack[i]);
                    nextsig = j + 1;
                    break;
                }
                    
 /* 
                {
                    if (sigindex == j)
                        throw runtime_error("Already signed with this privkey.");

                    verifiedSig = stack[i];
                    i++;
                    nextsig = j + 1;
                }
*/
                if (sigindex == j)
                {
                    if (verbose) cout << "signing. stack: " << i << "   pubkey: " << j << endl; 
                    uchar_vector sig = secp256k1_sign_rfc6979(signingKey, signingHash);
                    sig.push_back(Coin::SIGHASH_ALL);
                    newStack.push_back(sig);
                    nextsig = sigindex + 1;
                    didSign = true;
                    break;
                }
            }

            if (newStack.size() == minsigs) break;

            if (j == (int)pubkeys.size())
                throw runtime_error("Invalid signature.");

        }
/*
        if (newStack.size() == minsigs && !didSign)
            throw runtime_error("Transaction already signed");        
*/                  
        newStack.push_back(redeemscript);
        stack = newStack;

        if (verbose)
        {
            cout << endl << "witness: " << tx.witness.getSerialized(false).getHex() << endl;
            cout << endl << "tx: " << tx.getSerializedWithWitness().getHex() << endl;
        }
        else
        {
            cout << tx.getSerializedWithWitness().getHex() << endl;
        }
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}
