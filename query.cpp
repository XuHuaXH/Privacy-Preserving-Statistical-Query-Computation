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

const std::string DATAFOLDER = "../HEData";


int queryRequest() {
    int action;
    string filename;
    string result;
    std::cout << "This program is used to compute the following parameter based on your selected dataset: \n" << std::endl;
    std::cout << "\t1. Average\n" << std::endl;
    std::cout << "\t2. Minimum\n" << std::endl;
    std::cout << "\t3. Maximum\n" << std::endl;
    std::cout << "[Usage]: 1 <filename> \n" << std::endl;
    std::cout << "Please specify your request: " << std::endl;
    std::cin >> action;
    std::cout << "Please indicate the file: " << std::endl;
    std::cin  >> filename;

    result = std::to_string(action) + " " + filename;

    std::ofstream file;
    file.open(DATAFOLDER + "/query.txt");

    file << result;

    file.close();
    return 0;
}



int main() {

    queryRequest();
    return 0;
}