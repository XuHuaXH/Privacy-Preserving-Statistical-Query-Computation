#include "binfhecontext.h"
#include <iostream>
#include "palisade.h"

// these header files are needed for serialization
#include "binfhecontext-ser.h"
#include "utils/serialize-binary.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"



// these header files are needed for reading data
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <iomanip>


using namespace lbcrypto;
using namespace std;

// path where files will be written to
const std::string DATAFOLDER = "../HEData";

// file path for reading the query
const string QUERY_FILE = "/query.txt";


// parse the client query and return a vector of the form [action, ciphertext_file_name]
vector<string> parseQuery() {
    vector<string> query;
    ifstream queryFile;
    queryFile.open(DATAFOLDER + QUERY_FILE);

    if (!queryFile) {
        cerr << "Unable to open " + DATAFOLDER + QUERY_FILE << endl;
        exit(1);
    }
    string line;
    getline(queryFile, line);
    int index = line.find(' ');
    if (index == string::npos) {
        cerr << "invalid query" << endl;
        exit(1);
    }
    query.push_back(line.substr(0, index));
    query.push_back(line.substr(index + 1, line.length()));

    queryFile.close();
    cout << query[0] << " " << query[1] << endl;
    return query;
}

void decryptBinResult() {
    BinFHEContext bin_cc;

    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/bin_cc.txt", bin_cc, SerType::BINARY))
    {
        cerr << "Could not deserialize the cryptocontext" << std::endl;
        exit(1);
    }
    cout << "The cryptocontext has been deserialized." << std::endl;


    LWEPrivateKey bin_privateKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/bin_private_key.txt", bin_privateKey,
                                     SerType::BINARY)) {
        std::cerr << " Could not deserilize the private key" << std::endl;
        exit(1);
    }

    std::cout << "The private key has been deserialized" << std::endl;

    vector<LWECiphertext> ct;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/resultData/bin_result.txt", ct,
            SerType::BINARY)) {
        cerr << " Could not deserilize the ciphertext" << std::endl;
        exit(1);
    }

    std::cout << "The ciphertext has been deserialized" << std::endl;

    int res = 0;
    int factor = 32768; // 2^15

    for (LWECiphertext c : ct) {
        LWEPlaintext p;
        bin_cc.Decrypt(bin_privateKey, c, &p);
        res += factor * p;
        factor /= 2;
    }
    cout <<  "result is " << res << endl;
}


void decryptRealResult() {

    CryptoContext<DCRTPoly> real_cc;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/real_cc.txt", real_cc,
                                     SerType::BINARY)) {
        cerr << "Could not deserialize the real cryptocontext" << std::endl;
        exit(1);
    }
    cout << "The real cryptoContext has been deserialized" << std::endl;

    LPPrivateKey<DCRTPoly> real_privateKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/real_secret_key.txt",
                                     real_privateKey, SerType::BINARY)) {
        cerr << " Could not deserialize the real private key" << std::endl;
        exit(1);
    }

    Ciphertext<DCRTPoly> real_result;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/resultData/real_result.txt", real_result, SerType::BINARY)) {
        cerr << " Could not deserilize the ciphertext" << std::endl;
        exit(1);
    }

    std::cout << "The ciphertext has been deserialized" << std::endl;

    Plaintext p;
    real_cc->Decrypt(real_privateKey,real_result, &p);
    std::cout.precision(8);
    p->SetLength(1);
    cout <<  "result is " << p << endl;


}

int main() {

    string choice = parseQuery()[0];
    if (choice == "2" || choice == "3") {
        decryptBinResult();
    } else {
        decryptRealResult();
    }

    return 0;
}