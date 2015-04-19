#include <iostream>
#include <stdexcept>
#include <string>

#include <CoinCore/hash.h>
#include <CoinCore/secp256k1.h>

#include <CoinQ/CoinQ_script.h>

using namespace Coin;
using namespace CoinCrypto;
using namespace CoinQ::Script;

using namespace std;

int main(int argc, char* argv[])
{
    if (argc != 7)
    {
        cerr << "# Usage: " << argv[0] << " <pubkey A1> <pubkey A2> <pubkey B1> <pubkey B2> <pubkey C1> <pubkey C2>" << endl;
        return -1;
    }

    try
    {
        uchar_vector pubkeyA1(argv[1]);
        uchar_vector pubkeyA2(argv[2]);
        uchar_vector pubkeyB1(argv[3]);
        uchar_vector pubkeyB2(argv[4]);
        uchar_vector pubkeyC1(argv[5]);
        uchar_vector pubkeyC2(argv[6]);

        if (pubkeyA1.size() != 33 || pubkeyA2.size() != 33 || pubkeyB1.size() != 33 || pubkeyB2.size() != 33 || pubkeyC1.size() != 33 || pubkeyC2.size() != 33)
            throw runtime_error("Invalid pubkey length.");

//        uchar_vector redeemscript;
//        redeemscript += opPushData(        
    }
    catch (const exception& e)
    {
        cerr << "Error: " << e.what() << endl;
        return -2;
    }

    return 0;
}
