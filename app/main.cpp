#include <jwt-cpp/jwt.h>
#include <iostream>

#include <fstream>
#include <string>
#include <stdexcept>

std::string read_keys_token(const std::string& filename) {
    std::ifstream file(filename);

    if (!file.is_open()) {
        throw std::runtime_error("Failed to open the file: " + filename);
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>());
    file.close();

    return content;
}

void write_license_to_file(const std::string& filename, const std::string& content){
    std::ofstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open the file: " + filename);
    }

    //write content to file an close it
    file << content;
    file.close();
}

void create_new_signed_license(const std::string& filename, const std::string& priv_key_path, const std::string issuer, const std::chrono::seconds valid_time) {
    std::string rsa_priv_key;
    try {
        rsa_priv_key = read_keys_token(priv_key_path);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to open the file: " + priv_key_path);
    }
    
    auto newtoken = jwt::create()
					 .set_issuer(issuer)
					 .set_type("JWT")
					 .set_id("license-checking-with-publickey-crypto")
					 .set_issued_at(std::chrono::system_clock::now())
					 .set_expires_at(std::chrono::system_clock::now() + valid_time)
					 .set_payload_claim("version", jwt::claim(std::string{"some_version_0.1"}))
					 .sign(jwt::algorithm::rs256("", rsa_priv_key, "", ""));

    try {
        write_license_to_file(filename,newtoken);
        std::cout << "new license file written successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        throw std::runtime_error("Failed to write license to file: "+ filename);
    }
}



int main() {
    
    std::string privateKeyfilepath = "PATH_TO_YOUR_PRIVATE_KEY";
    std::string licensefilename = "PATH_TO_LICENSEFILE_license.txt";
    std::string publicKeyfilepath = "PATH_TO_YOUR_PUBLIC_KEY";

    //create an example license that is valid for a whole year
    create_new_signed_license(licensefilename, privateKeyfilepath, "Kaushik", std::chrono::seconds{31536000});

    std::string token;
     
    try {
        token = read_keys_token(licensefilename);
        std::cout << "RSA signed JWT: " << token << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 0;
    }

    std::string rsa_pub_key;
    
    try {
        rsa_pub_key = read_keys_token(publicKeyfilepath);
        std::cout << "public key for verification: " << rsa_pub_key << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 0;
    }

    //now verify the JWT-license:
    auto decoded = jwt::decode(token);
    try{
        auto verify = jwt::verify().allow_algorithm(jwt::algorithm::rs256(rsa_pub_key, "", "", "")).with_issuer("Kaushik");
        verify.verify(decoded);
    } catch (const std::exception& e) {
        std::cout << "Buy a proper License!!!" << std::endl;
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
    //show some license properties:
    for (auto& e : decoded.get_header_json())
		std::cout << e.first << " = " << e.second << std::endl;

    for(auto& e : decoded.get_payload_json())
        std::cout << e.first << " = " << e.second << std::endl;


    //example with a wrong parameter:
    auto verify = jwt::verify().allow_algorithm(jwt::algorithm::rs256(rsa_pub_key, "", "", "")).with_issuer("Kpy");
    verify.verify(decoded);

    //further verification steps e.g. expiration time relativ to some time server time....

}

