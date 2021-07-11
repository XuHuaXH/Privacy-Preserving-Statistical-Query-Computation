#include "binfhecontext.h"
#include <iostream>
#include "palisade.h"

// these header files are needed for serialization
#include "binfhecontext-ser.h"
#include "utils/serialize-binary.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"

// These libraries used for CKKS
#include "palisade.h"
#include "utils/serialize-binary.h"
#include <iomanip>
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/ckks/ckks-ser.h"
#include "pubkeylp-ser.h"
#include <tuple>
#include <unistd.h>

// these header files are needed for read csv data
#include <vector>
#include <string>
#include <fstream>
#include <utility>
#include <stdexcept>
#include <sstream>

// these header files are needed for type info
#include <type_traits>
#include <typeinfo>
#ifndef _MSC_VER
#   include <cxxabi.h>
#endif
#include <memory>
#include <string>
#include <cstdlib>

// these header files are needed for floor
#include <math.h>

using namespace lbcrypto;
using namespace std;

// path where files will be written to
const string DATAFOLDER = "../HEData";



vector<pair<string, vector<double>>> read_csv(string filename){
    // Reads a CSV file into a vector of <string, vector<int>> pairs where
    // each pair represents <column name, column values>

    // Create a vector of <string, int vector> pairs to store the result
    vector<pair<string, vector<double>>> result;

    // Create an input filestream
    ifstream myFile(filename);

    // Make sure the file is open
    if(!myFile.is_open()) throw runtime_error("Could not open file");

    // Helper vars
    string line, colname;
    int val;

    // Read the column names
    if(myFile.good())
    {
        // Extract the first line in the file
        getline(myFile, line);

        // Create a stringstream from line
        stringstream ss(line);

        // Extract each column name
        while(getline(ss, colname, ',')){

            // Initialize and add <colname, int vector> pairs to result
            result.push_back({colname, vector<double> {}});
        }
    }

    // Read data, line by line
    while(getline(myFile, line))
    {
        // Create a stringstream of the current line
        stringstream ss(line);

        // Keep track of the current column index
        int colIdx = 0;

        // Extract each integer
        while(ss >> val){

            // Add the current integer to the 'colIdx' column's values vector
            result.at(colIdx).second.push_back(val);

            // If the next token is a comma, ignore it and move on
            if(ss.peek() == ',') ss.ignore();

            // Increment the column index
            colIdx++;
        }
    }

    // Close file
    myFile.close();

    return result;
}

vector<int> binaryConversion(int n)
{
    vector<int> result;
    int r;
    int i = 0;
    while(n!=0) {
        r = n % 2;
        result.insert(result.begin(), r);
        n /= 2;
        i += 1;
    }
    while(i <= 15) {
        result.insert(result.begin(), 0);
        i += 1;
    }

    return result;
}



int binKeyGeneration() {

    // ------------------------------------------ Key Generation  -------------------------------------------------

    // Generating the crypto context

    auto cc_bin = BinFHEContext();

    cc_bin.GenerateBinFHEContext(STD128);

    // Generating the secret key

    auto sk = cc_bin.KeyGen();

    // Generating the bootstrapping keys

    cc_bin.BTKeyGen(sk);

    cout << "All Keys have generated." << endl;


    // --------------------------------------- Serilization -----------------------------------------------------

    // Serialization of Keys

    if (!Serial::SerializeToFile(DATAFOLDER + "/keyData/bin_cc.txt", cc_bin, SerType::BINARY)) {
        cerr << " Error serializing the cryptocontext" << endl;

        return 1;
    }

    cout << "The cryptocontext has been serialized" << endl;


    if (!Serial::SerializeToFile(DATAFOLDER + "/keyData/bin_refreshing_key.txt", cc_bin.GetRefreshKey(), SerType::BINARY)) {
        cerr << " Error serializing the refreshing key" << endl;

        return 1;
    }

    if (!Serial::SerializeToFile(DATAFOLDER + "/keyData/bin_switching_key.txt", cc_bin.GetSwitchKey(), SerType::BINARY)) {
        cerr << " Error serializing the switching key" << endl;

        return 1;
    }

    cout << "The refreshing key and switching key has been serialized" << endl;


    if (!Serial::SerializeToFile(DATAFOLDER + "/keyData/bin_private_key.txt", sk, SerType::BINARY)) {
        cerr << " Error serializing the private key" << endl;

        return 1;
    }

    cout << "The private key has been serialized" << endl;

    return 0;

}


int realKeyGeneration() {
// ------------------------------ Key Generation -------------------------------------------------------

    // ~~~~~~~~~ Set 1: CryptoContext ~~~~~~~~~~
    uint32_t multDepth = 1;
    uint32_t scaleFactorBits = 50;
    uint32_t batchSize = 1;
    SecurityLevel securityLevel = HEStd_128_classic;

    CryptoContext<DCRTPoly> cryptoContext =
        CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
                multDepth, scaleFactorBits, batchSize, securityLevel);
    cout << "CKKS scheme is using ring dimension " << cryptoContext->GetRingDimension() <<
    endl << endl;

    // Enable features
    cryptoContext->Enable(ENCRYPTION);
    cryptoContext->Enable(SHE);

    cout << "\nThe cryptocontext has been generated." << endl;

    // ~~~~~~~~~ Set 2: key pair ~~~~~~~~~~~~~~~~~~
    LPKeyPair<DCRTPoly> keys = cryptoContext->KeyGen();
    cout << "\nThe key pairs have been generated." << endl;

    cryptoContext->EvalMultKeyGen(keys.secretKey);
    cryptoContext->EvalAtIndexKeyGen(keys.secretKey, {1, 2, -1, -2});

    cout << "\nThe relinearization key and rotation keys have been generated." << endl;

    // ------------------------------- serialization -------------------------------------------------------
    // ~~~~~~~~~~ Set 1: CryptoContext ~~~~~~~~~~~~~~~~~~~~
    if (!Serial::SerializeToFile(DATAFOLDER + "/keyData/real_cc.txt", cryptoContext, SerType::BINARY)) {
        cerr << " Error serializing the cryptocontext" << endl;
        return 1;
    }

    cout << "The cryptocontext has been serialized." << endl;

    // ~~~~~~~~~ Set 2: Key Pair ~~~~~~~~~~~~~~~~~~~~~~~~~~
    if (!Serial::SerializeToFile(DATAFOLDER + "/keyData/real_public_key.txt", keys.publicKey, SerType::BINARY)) {
        cerr << " Error serializing the Public key" << endl;

        return 1;
    }

    if (!Serial::SerializeToFile(DATAFOLDER + "/keyData/real_secret_key.txt", keys.secretKey, SerType::BINARY)) {
        cerr << " Error serializing the Private key" << endl;

        return 1;
    }

    cout << "The public and private key have been serialized" << endl;

    return 0;
}


int dataEncryption(vector<pair<string, vector<double>>> testData){

    // ------------------------------ deserialization ------------------------------------------------------
    // ~~~~~~~~~~ Set 1: CryptoContext ~~~~~~~~~~~~~
    BinFHEContext bin_cc;

    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/bin_cc.txt", bin_cc, SerType::BINARY))
    {
        cerr << "Could not deserialize the bin cryptocontext" << endl;

        return 1;
    }

    cout << "The bin CryptoContext has been deserialized" << endl;

    shared_ptr<RingGSWBTKey> bin_refreshKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/bin_refreshing_key.txt",
            bin_refreshKey, SerType::BINARY))
    {
        cerr << " Cound not deserialize the refreshing key" << endl;

        return 1;
    }


    shared_ptr<LWESwitchingKey> bin_switchKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/bin_switching_key.txt",
            bin_switchKey, SerType::BINARY))
    {
        cerr << " Could not deserialize the switching key" << endl;

        return 1;
    }

    cout << "The refreshing key and switching key has been deserialized" << endl;

    // Loading the keys in the cryptocontext

    bin_cc.BTKeyLoad({bin_refreshKey, bin_switchKey});

    LWEPrivateKey bin_privateKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/bin_private_key.txt", bin_privateKey,
            SerType::BINARY)) {
        cerr << " Could not deserialize the private key" << endl;

        return 1;
    }

    cout << "The bin private key has been deserialized" << endl;


    CryptoContext<DCRTPoly> real_cc;

    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/real_cc.txt", real_cc,
            SerType::BINARY))
    {
        cerr << "Could not deserialize the int cryptocontext" << endl;
        return 1;
    }

    cout << "The cryptocontext has been deserialized." << endl;

    // ~~~~~~~~~~~~ Set 2: Public Key ~~~~~~

    LPPublicKey<DCRTPoly> real_publicKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/real_public_key.txt", real_publicKey,
            SerType::BINARY))
    {
        cerr << " Could not deserialize the public key" << endl;

        return 1;
    }

    cout << "The public key has been deserialized" << endl;


    // Deserilizing secret key

    LWEPrivateKey bin_sk;
    if (!Serial::DeserializeFromFile(DATAFOLDER + "/keyData/bin_private_key.txt", bin_sk,
            SerType::BINARY)) {
        cerr << " Could not deserialize the private key" << endl;

        return 1;
    }

    cout << "The private key has been deserialized" << endl;


    // ------------------------------ Encrypting Data ------------------------------------------------------

    int col_size = testData.size();
    int row_size = testData.at(0).second.size();


    // real number encryption (CKKS)
    for(int j = 0; j < col_size; ++j)
    {
        vector<Ciphertext<DCRTPoly>> ciphertext_vector;

        for(int i = 0; i < row_size; ++i)
        {
            double plaindata = testData.at(j).second.at(i);
            vector<complex<double>> rawdataHolder;
            rawdataHolder.push_back(plaindata);
            Plaintext ptxt = real_cc->MakeCKKSPackedPlaintext(rawdataHolder);
            auto cipherdata = real_cc->Encrypt(real_publicKey, ptxt);
            ciphertext_vector.push_back(cipherdata);
        }


        if (!Serial::SerializeToFile(DATAFOLDER + "/outData/" + "real_ciphertext_" + to_string
        (j) + ".txt", ciphertext_vector, SerType::BINARY)) {
            cerr << " Error writing serialization of ciphertext" << endl;

            return 1;
        }
        cout << "The ciphertext have been serialized." << endl;
    }


    // double number encryption (FHEW)
    for(int j = 0; j < col_size; ++j)
    {
        vector<vector<LWECiphertext>> ciphertext_vector;

        for(int i = 0; i < row_size; ++i)
        {
            double rawData = testData.at(j).second.at(i);
            int checker = int(rawData - floor(rawData));
            vector<int> binaryData;
            if (checker == 0) {
                binaryData = binaryConversion(int(rawData));
            }
            else {
                // dump what after the period
                binaryData = binaryConversion(int(rawData));
            }
            cout << "encrypting binary data " << binaryData << endl;

            vector<LWECiphertext> tempVector;
            for(int k = 0; k < int(binaryData.size()); k++)
            {
                int rawBit = binaryData[k];
                auto cipherdata = bin_cc.Encrypt(bin_privateKey, rawBit);
                tempVector.push_back(cipherdata);
            }

            ciphertext_vector.push_back(tempVector);
        }


        if (!Serial::SerializeToFile(DATAFOLDER + "/outData/" + "bin_ciphertext_" + to_string(j)
        + ".txt", ciphertext_vector, SerType::BINARY)) {
            cerr << " Error writing serialization of ciphertext" << endl;

            return 1;
        }
        cout << "The ciphertext have been serialized." << endl;
    }


    return 0;
}


int main() {
    // --------------------------------- Read Data -----------------------------------------
    vector<pair<string, vector<double>>> testData = read_csv(DATAFOLDER + "/testData.csv");

    realKeyGeneration();
    binKeyGeneration();
    dataEncryption(testData);

    return 0;
}
