#include <CoinCore/hash.h>
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
    if (argc < 3)
    {
        cerr << "# Usage: " << argv[0] << " <minsigs> <pubkey1> [pubkey2] ..." << endl;
        return -1;
    }

    try
    {
        int minsigs = strtol(argv[1], NULL, 0);
        if (minsigs < 1 || minsigs > 15)
            throw runtime_error("Invalid minsigs.");

        vector<uchar_vector> pubkeys;
        for (int i = 2; i < argc; i++)
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

        uchar_vector txoutscript;
        txoutscript << OP_HASH160 << pushStackItem(hash160(witnessscript)) << OP_EQUAL;

        cout << getAddressForTxOutScript(txoutscript, ADDRESS_VERSIONS) << endl;
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}
