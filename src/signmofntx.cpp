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
    if (argc != 3)
    {
        cerr << "# Usage: " << argv[0] << " <rawtx> <privkey>" << endl;
        return -1;
    }

    try
    {
        uchar_vector rawtx(argv[1]);
        Transaction tx(rawtx);
        if (tx.inputs.size() != 1)
            throw runtime_error("Invalid transaction.");

        uchar_vector privkey(argv[2]);
        if (privkey.size() != 32) throw runtime_error("Invalid private key length.");

        secp256k1_key signingKey;
        signingKey.setPrivKey(privkey);
        uchar_vector pubkey = signingKey.getPubKey();

        SignableTxIn signableTxIn(tx, 0);
        uchar_vector sigHash = tx.getSigHash(Coin::SIGHASH_ALL, 0, signableTxIn.redeemscript());
        uchar_vector sig = secp256k1_sign_rfc6979(signingKey, sigHash);
        sig.push_back(Coin::SIGHASH_ALL);
        signableTxIn.addsig(pubkey, sig);
        tx.inputs[0].scriptSig = signableTxIn.txinscript();

        cout << tx.getSerialized().getHex() << endl;
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}
