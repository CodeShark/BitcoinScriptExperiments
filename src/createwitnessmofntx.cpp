#include <CoinCore/hash.h>
#include <CoinCore/numericdata.h>
#include <CoinCore/secp256k1_openssl.h>

#include <CoinQ/CoinQ_script.h>

#include <algorithm>
#include <iostream>
#include <stdexcept>

const unsigned char ADDRESS_VERSIONS[] = {30, 50};

using namespace Coin;
using namespace CoinCrypto;
using namespace CoinQ::Script;

using namespace std;

int main(int argc, char* argv[])
{
    if (argc < 7)
    {
        cerr << "# Usage: " << argv[0] << " <address> <amount> <outpoint hash> <outpoint index> <minsigs> <pubkey1> [pubkey2] ..." << endl;
        return -1;
    }

    try
    {
        string address(argv[1]);
        uint64_t amount = strtoull(argv[2], NULL, 0);
        TxOut txOut(amount, getTxOutScriptForAddress(address, ADDRESS_VERSIONS));

        uchar_vector outpointHash(argv[3]);
        if (outpointHash.size() != 32) throw runtime_error("Invalid outpoint hash.");
        uint32_t outpointIndex = strtoul(argv[4], NULL, 0);
        OutPoint outPoint(outpointHash, outpointIndex);

        int minsigs = strtol(argv[5], NULL, 0);
        if (minsigs < 1 || minsigs > 15)
            throw runtime_error("Invalid minsigs.");

        vector<uchar_vector> pubkeys;
        for (int i = 6; i < argc; i++)
        {
            uchar_vector pubkey(argv[i]);
            if (pubkey.size() != 33)
                throw runtime_error("Invalid pubkey length.");

            pubkeys.push_back(pubkey);
        }

        if (minsigs > pubkeys.size())
            throw runtime_error("Too few pubkeys.");

        if (pubkeys.size() > 15)
            throw runtime_error("Too many pubkeys.");

        sort(pubkeys.begin(), pubkeys.end());

        uchar_vector redeemscript;
        redeemscript << (OP_1_OFFSET + minsigs);
        for (auto& pubkey: pubkeys)
        {
            redeemscript << pushStackItem(pubkey);
        }
        redeemscript << (OP_1_OFFSET + pubkeys.size()) << OP_CHECKMULTISIG;

        uchar_vector witnessscript;
        witnessscript << OP_1 << pushStackItem(sha256(redeemscript));

        TxIn txIn(outPoint, pushStackItem(witnessscript), 0);

        Transaction tx;
        tx.version = 1;
        tx.inputs.push_back(txIn);
        tx.outputs.push_back(txOut);
        tx.lockTime = 0;

        tx.inputs[0].scriptWitness.push(redeemscript);

        cout << tx.getSerializedWithWitness().getHex() << endl;
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}
