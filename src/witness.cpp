#include <iostream>
#include <stdexcept>

#include "scriptnum.h"

#include <CoinCore/hash.h>
#include <CoinCore/secp256k1_openssl.h>

#include <CoinQ/CoinQ_script.h>

const unsigned char ADDRESS_VERSIONS[] = {30, 50};

using namespace Coin;
using namespace CoinCrypto;
using namespace CoinQ::Script;

using namespace std;

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        cerr << "# Usage: " << argv[0] << " <pubkey>" << endl;
        return -1;
    }

    try
    {
        uchar_vector pubkey(argv[1]);
        if (pubkey.size() != 33) throw runtime_error("Invalid pubkey length.");

        uchar_vector redeemscript;
        redeemscript += opPushData(pubkey.size());
        redeemscript += pubkey;
        redeemscript.push_back(OP_CHECKSIG);

        cout << endl << "redeemscript: " << redeemscript.getHex() << endl;

        uchar_vector scripthash = sha256(redeemscript);
        uchar_vector witnessscript;
        witnessscript.push_back(OP_1);
        witnessscript += opPushData(scripthash.size());
        witnessscript += scripthash;

        cout << endl << "witnessscript: " << witnessscript.getHex() << endl;

        uchar_vector txoutscript;
        txoutscript.push_back(OP_HASH160);
        txoutscript.push_back(0x14);
        txoutscript += ripemd160(sha256(witnessscript));
        txoutscript.push_back(OP_EQUAL);
        cout << endl << "address: " << getAddressForTxOutScript(txoutscript, ADDRESS_VERSIONS) << endl;

        OutPoint outPoint(bytes_t(32, 0), 0);
        TxIn txIn(outPoint, witnessscript, 0);
        TxOut txOut(100000, bytes_t());
        Transaction tx;
        tx.version = 0;
        tx.inputs.push_back(txIn);
        tx.outputs.push_back(txOut);

        cout << endl << "tx: " << tx.getSerialized().getHex() << endl; 
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}
