#include "binfhecontext.h"

// these header files are needed for serialization
#include "binfhecontext-ser.h"
#include "utils/serialize-binary.h"
#include "utils/sertype.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "scheme/ckks/ckks-ser.h"
#include "pubkeylp-ser.h"
#include "palisade.h"

#include <vector>
#include <fstream>
#include <iomanip>
#include <tuple>
#include <unistd.h>
#include <ctime>



using namespace lbcrypto;
using namespace std;

/*
 * Assuming the integers are represented in Big Endian
 * Asssuming input integers on the client side range form [-2^14, 2^14 - 1]
 */

// path where files will be written to
const std::string DATAFOLDER = "../HEData";

// file path for reading the query
const string QUERY_FILE = "/query.txt";

// file path for reading the contexts and keys
const string KEY_FOLDER = "/keyData";

// file path for reading the ciphertexts
const string CIPHERTEXT_FOLDER = "/outData";

// file path for writing the computation result
const string RESULT_FOLDER = "/resultData";

// number of bits used to represent an integer
const int NUM_OF_BITS = 16;
const auto SERIALIZATION_TYPE = SerType::BINARY;


void DeserializeBinContext(BinFHEContext& cc) {
    if (!Serial::DeserializeFromFile(DATAFOLDER + KEY_FOLDER + "/bin_cc.txt", cc,
            SERIALIZATION_TYPE)) {
        cerr << "Failed to deserialize the BinFHE cryptocontext" << endl;
        exit(1);
    }
}

shared_ptr<RingGSWBTKey> DeserializeRefreshingKey(BinFHEContext& cc) {
    shared_ptr<RingGSWBTKey> refreshKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + KEY_FOLDER + "/bin_refreshing_key.txt",
            refreshKey,
            SERIALIZATION_TYPE)) {
        cerr << "Could not deserialize the refresh key" << endl;
        exit(1);
    }
    cout << "The refresh key has been deserialized." << std::endl;
    return refreshKey;
}

shared_ptr<LWESwitchingKey> DeserializeSwitchingKey(BinFHEContext& cc) {
    shared_ptr<LWESwitchingKey> ksKey;
    if (!Serial::DeserializeFromFile(DATAFOLDER + KEY_FOLDER + "/bin_switching_key.txt", ksKey,
            SERIALIZATION_TYPE)) {
        cerr << "Could not deserialize the switching key" << endl;
        exit(1);
    }
    cout << "The switching key has been deserialized." << endl;
    return ksKey;
}

// deserialize a list of encrypted integers(in bit array form) from the file filePath
void DeserializeBinData(vector<vector<LWECiphertext>>& data, const string&
filePath) {
    if (!Serial::DeserializeFromFile(DATAFOLDER + CIPHERTEXT_FOLDER + "/" + filePath, data,
            SERIALIZATION_TYPE)) {
        cerr << "Error deserializing 2D binary ciphertext array" << endl;
        exit(1);
    }
}


void SerializeBinResult(const vector<LWECiphertext>& result) {
    if (!Serial::SerializeToFile(DATAFOLDER + RESULT_FOLDER + "/bin_result.txt", result,
            SERIALIZATION_TYPE)) {
        cerr << "Error serializing BinResult" << endl;
        exit(1);
    }
}


void DeserializeRealContext(CryptoContext<DCRTPoly>& serverCC) {
    if (!Serial::DeserializeFromFile(DATAFOLDER + KEY_FOLDER + "/real_cc.txt", serverCC,
            SERIALIZATION_TYPE)) {
        cerr << "failed to deserialize real context" << endl;
        exit(1);
    }
}

void DeserializeRealPK(LPPublicKey<DCRTPoly>& publicKey) {
    if (!Serial::DeserializeFromFile(DATAFOLDER + KEY_FOLDER + "/real_public_key.txt", publicKey,
            SERIALIZATION_TYPE)) {
        std::cerr << "failed to deserialize real public key" << endl;
        std::exit(1);
    }
}

// deserialize a list of encrypted doubles from the file filePath
void DeserializeRealData(vector<Ciphertext<DCRTPoly>>& data, const string& filePath) {
    if (!Serial::DeserializeFromFile(DATAFOLDER + CIPHERTEXT_FOLDER + "/" + filePath, data,
            SERIALIZATION_TYPE)) {
        cerr << "Error deserializing 1D real ciphertext array" << endl;
        exit(1);
    }
}

void SerializeRealResult(const Ciphertext<DCRTPoly>& result) {
    if (!Serial::SerializeToFile(DATAFOLDER + RESULT_FOLDER + "/real_result.txt", result,
            SERIALIZATION_TYPE)) {
        cerr << "Error serializing realResult" << endl;
        exit(1);
    }
}




// parse the client query and return a vector of the form [action, ciphertext_file_name]
vector<string> parseQuery() {
    vector<string> query;
    ifstream queryFile;
    queryFile.open(DATAFOLDER + QUERY_FILE);

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



template <class T>
void reverse(vector<T>& vec) {
    int i = 0;
    int j = vec.size() - 1;
    while (i < j) {
        T tmp = vec[i];
        vec[i] = vec[j];
        vec[j] = tmp;
        i++;
        j--;
    }
}




vector<LWECiphertext> sub(const BinFHEContext& cc, vector<LWECiphertext>
c1, vector<LWECiphertext> c2) {

    // input validation
    if (c1.size() != c2.size()) {
        cerr << "sub: Two input ciphertext vectors must have the same size." << endl;
        exit(1);
    }

    // compute the encryption of 1 from the given data
    LWECiphertext copy = cc.Bootstrap(c1[0]);
    auto borrow = cc.EvalNOT(cc.EvalBinGate(XOR, copy, c1[0])); // borrow is initialized to one


    vector<LWECiphertext> diff;
    cout << "start computing diff" << endl;
    for (int i = c1.size() - 1; i >= 0; --i) {
        diff.push_back(cc.EvalBinGate(XOR, borrow, cc.EvalBinGate(XOR, c1[i], cc.EvalNOT(c2[i]))));

        // computes the new borrow bit
        LWECiphertext val1 = cc.EvalBinGate(AND, c1[i], cc.EvalNOT(c2[i]));
        LWECiphertext val2 = cc.EvalBinGate(AND, borrow, c1[i]);
        LWECiphertext val3 = cc.EvalBinGate(AND, borrow, cc.EvalNOT(c2[i]));
        borrow = cc.EvalBinGate(OR, val1, cc.EvalBinGate(OR, val2, val3));
    }
    reverse(diff);
    cout << "finished computing diff" << endl;
    return diff;
}


vector<LWECiphertext> mul(const BinFHEContext& cc, const LWECiphertext& scalar,
                          const vector<LWECiphertext>& ct) {
    vector<LWECiphertext> prod;
    cout << "start computing multiplication" << endl;
    for (int i = 0; i < ct.size(); ++i) {
        prod.push_back(cc.EvalBinGate(AND, scalar, ct[i]));

    }
    cout << "finished computing multiplication" << endl;
    return prod;
}


vector<LWECiphertext> addNoCarry(const BinFHEContext& cc, const vector<LWECiphertext>& c1,
                                 const vector<LWECiphertext>& c2) {
    vector<LWECiphertext> result;
    for (int i = 0; i < c1.size(); ++i) {
        result.push_back(cc.EvalBinGate(XOR, c1[i], c2[i]));
    }
    return result;
}


// compare data[i] and data[j], swap the smaller one to data[i]
void CmpAndSwapMin(const BinFHEContext& cc, vector<vector<LWECiphertext>>&
data, int i, int j) {
    cout << "start computing cmp bit" << endl;
    vector<LWECiphertext> diff = sub(cc, data[i], data[j]);
    LWECiphertext sigBit = diff[0];

    LWECiphertext notSigBit = cc.EvalNOT(sigBit);
    cout << "start swapping" << endl;
    vector<LWECiphertext> temp = addNoCarry(cc, mul(cc, sigBit, data[i]), mul(cc, notSigBit,
                                                                              data[j]));
    data[j] = addNoCarry(cc, mul(cc, notSigBit, data[i]), mul(cc, sigBit, data[j]));
    data[i] = temp;
    cout << "finished swapping" << endl;
}

// compare data[i] and data[j], swap the larger one to data[i]
void CmpAndSwapMax(const BinFHEContext& cc, vector<vector<LWECiphertext>>&
data, int i, int j) {
    cout << "start computing cmp bit" << endl;
    vector<LWECiphertext> diff = sub(cc, data[i], data[j]);
    LWECiphertext sigBit = diff[0];

    LWECiphertext notSigBit = cc.EvalNOT(sigBit);
    cout << "start swapping" << endl;
    vector<LWECiphertext> temp = addNoCarry(cc, mul(cc, notSigBit, data[i]), mul(cc, sigBit,
                                                                              data[j]));
    data[j] = addNoCarry(cc, mul(cc, sigBit, data[i]), mul(cc, notSigBit, data[j]));
    data[i] = temp;
    cout << "finished swapping" << endl;
}


// finds the ciphertext whose plaintext has the minimum value
// Note: this function modifies all the ciphertext arrays in the list
vector<LWECiphertext> FindMin(const BinFHEContext& cc, vector<vector<LWECiphertext>>& data) {
    for (int i = 1; i < data.size(); ++i) {
        CmpAndSwapMin(cc, data, 0, i);
    }
    return data[0];
}

// finds the ciphertext whose plaintext has the maximum value
// Note: this function modifies all the ciphertext arrays in the list
vector<LWECiphertext> FindMax(const BinFHEContext& cc, vector<vector<LWECiphertext>>& data) {
    for (int i = 1; i < data.size(); ++i) {
        CmpAndSwapMax(cc, data, 0, i);
    }
    return data[0];
}


Ciphertext<DCRTPoly> FindAverage(const CryptoContext<DCRTPoly>& cc, const
LPPublicKey<DCRTPoly>& publicKey, const vector<Ciphertext<DCRTPoly>>& data) {
    auto count = (double)data.size();
    auto sum = cc->EvalAddMany(data);
    return cc->EvalMult(sum, 1.0 / count);
}


void executeQuery(vector<string> query) {
    if (query.size() != 2) {
        cerr << "query must have 2 elements" << endl;
        exit(1);
    }
    string action = query[0];
    string filePath = query[1];
    if (action != "1" && action != "2" && action != "3") {
        cerr << "invalid action in query" << endl;
        exit(1);
    }

    if (action == "2" || action == "3") {

        // recover context and ciphertext data
        BinFHEContext cc;
        DeserializeBinContext(cc);
        auto refreshKey = DeserializeRefreshingKey(cc);
        auto ksKey = DeserializeSwitchingKey(cc);

        // Loading the keys in the cryptocontext
        cc.BTKeyLoad({refreshKey, ksKey});

        vector<vector<LWECiphertext>> data;
        DeserializeBinData(data, filePath);

        vector<LWECiphertext> result = action == "2" ? FindMin(cc, data) : FindMax(cc, data);
        SerializeBinResult(result);
    } else {

        // recover context, pk and ciphertext data
        CryptoContext<DCRTPoly> cc;
        LPPublicKey<DCRTPoly> publicKey;
        DeserializeRealContext(cc);
        DeserializeRealPK(publicKey);
        vector<Ciphertext<DCRTPoly>> data;
        DeserializeRealData(data, filePath);

        Ciphertext<DCRTPoly> result = FindAverage(cc, publicKey, data);
        SerializeRealResult(result);
    }
}


void testAddNoCarry(const BinFHEContext& cc,  ConstLWEPrivateKey sk, const vector<LWECiphertext>&
        c1, const
vector<LWECiphertext>& c2) {
    vector<LWECiphertext> sum = addNoCarry(cc, c1, c2);
    vector<LWEPlaintext> result(c1.size());
    for (int i = 0; i < result.size(); ++i) {
        cc.Decrypt(sk, sum[i], &result[i]);
    }
    for (LWEPlaintext p : result) {
        cout << p << " ";
    }
}

void testMul(const BinFHEContext& cc, ConstLWEPrivateKey sk, const LWECiphertext& c1, const
vector<LWECiphertext>& c2) {
    vector<LWECiphertext> sum = mul(cc, c1, c2);
    vector<LWEPlaintext> result(c2.size());
    for (int i = 0; i < result.size(); ++i) {
        cc.Decrypt(sk, sum[i], &result[i]);
    }
    for (LWEPlaintext p : result) {
        cout << p << " ";
    }
}

void testSub(const BinFHEContext& cc,  ConstLWEPrivateKey sk, const
vector<LWECiphertext>& c1, const vector<LWECiphertext>& c2) {
    vector<LWECiphertext> diff = sub(cc, c1, c2);
    vector<LWEPlaintext> result(c2.size());
    for (int i = 0; i < result.size(); ++i) {
        cc.Decrypt(sk, diff[i], &result[i]);
    }
    for (LWEPlaintext p : result) {
        cout << p << " ";
    };
}

void testMin(const BinFHEContext& cc,  ConstLWEPrivateKey sk, vector<vector<LWECiphertext>>& ct) {
    cout << "start finding min" << endl;
    vector<LWECiphertext> min = FindMin(cc, ct);
    cout << "finished finding min" << endl;
    vector<LWEPlaintext> result(NUM_OF_BITS);
    cout << "min has size " << min.size() << endl;
    for (int i = 0; i < min.size(); ++i) {
        cc.Decrypt(sk, min[i], &result[i]);
    }

    for (int i = 0; i < result.size(); ++i) {
        cout << result[i] << " ";
    }
}


void testMax(const BinFHEContext& cc,  ConstLWEPrivateKey sk, vector<vector<LWECiphertext>>& ct) {
    cout << "start finding max" << endl;
    vector<LWECiphertext> max = FindMax(cc, ct);
    cout << "finished finding max" << endl;
    vector<LWEPlaintext> result(NUM_OF_BITS);
    cout << "max has size " << max.size() << endl;
    for (int i = 0; i < max.size(); ++i) {
        cc.Decrypt(sk, max[i], &result[i]);
    }

    for (int i = 0; i < result.size(); ++i) {
        cout << result[i] << " ";
    }
}

void testAverage() {
    uint32_t multDepth = 1;
    uint32_t scaleFactorBits = 50;
    uint32_t batchSize = 1;
    SecurityLevel securityLevel = HEStd_128_classic;
    CryptoContext<DCRTPoly> cc =
            CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
                    multDepth, scaleFactorBits, batchSize, securityLevel);

    std::cout << "CKKS scheme is using ring dimension " << cc->GetRingDimension() << std::endl;

    cc->Enable(ENCRYPTION);
    cc->Enable(SHE);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    complex<double> n1(15.4, 0.0);
    complex<double> n2(3.6, 0.0);
    complex<double> n3(7.3, 0.0);
    vector<complex<double>> x1 = {n1};
    vector<complex<double>> x2 = {n2};
    vector<complex<double>> x3 = {n3};

    Plaintext p1 = cc->MakeCKKSPackedPlaintext(x1);
    Plaintext p2 = cc->MakeCKKSPackedPlaintext(x2);
    Plaintext p3 = cc->MakeCKKSPackedPlaintext(x3);
    Ciphertext<DCRTPoly> c1 = cc->Encrypt(keys.publicKey, p1);
    auto c2 = cc->Encrypt(keys.publicKey, p2);
    auto c3 = cc->Encrypt(keys.publicKey, p3);
    auto sum = cc->EvalAdd(c1, cc->EvalAdd(c2, c3));
    auto avg = cc->EvalMult(sum, 1.0 / 3.0);
    Plaintext res;
    std::cout.precision(8);
    cc->Decrypt(keys.secretKey, avg, &res);
    res->SetLength(batchSize);
    cout << res << endl;

}


int main() {

    vector<string> query = parseQuery();
    executeQuery(query);

}
