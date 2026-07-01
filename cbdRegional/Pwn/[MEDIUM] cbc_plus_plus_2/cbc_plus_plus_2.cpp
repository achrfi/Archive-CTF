// g++ cbc_plus_plus_2.cpp -o cbc_plus_plus_2 -Wl,-z,relro,-z,now -no-pie -O0

#include<iostream>
#include<string>
#include<vector>
#include<algorithm>

static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64_encode(const std::string& input) {
    std::string output;
    int val = 0, valb = -6;

    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            output.push_back(alphabet[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) output.push_back(alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
    while(output.length() % 4 != 0) output.push_back('=');

    return output;
}

std::string rot13(const std::string& input) {
    std::string output = input;

    for (char& c : output) {
        if (c >= 'a' && c <= 'z') {
            c = 'a' + (c - 'a' + 13) % 26;
        } else if (c >= 'A' && c <= 'Z') {
            c = 'A' + (c - 'A' + 13) % 26;
        }
    }

    return output;
}

void reverse_string(std::string& input) {
    std::reverse(input.begin(), input.end());
    return;
}

void init(std::string &main_str) {
    std::cout << "Enter string: ";
    std::cin >> main_str;
}

void menu() {
    std::cout << "1. Base64" << std::endl;
    std::cout << "2. Rot13" << std::endl;
    std::cout << "3. Reverse" << std::endl;
    std::cout << "4. Option history" << std::endl;
    std::cout << "5. Exit" << std::endl;
    std::cout << "> ";
}

void encoder(std::string &main_str, std::vector<unsigned long long> &history) {

    unsigned int choice = 0;
    char buf[0x10];

    while(1) {

        std::cout << main_str << std::endl;
        menu();
        std::cin >> buf;
        choice = (unsigned int)atoi(buf);
        if(!std::cin.good()) break;
        history.push_back(choice);
        switch(choice)  {
            case 1:
                main_str = base64_encode(main_str);
                break;
            case 2:
                main_str = rot13(main_str);
                break;
            case 3:
                reverse_string(main_str);
                break;
            case 4:
                std::cout << "Option history:" << std::endl;
                for(auto choice : history) {
                    std::cout << choice << std::endl;
                }
                break;
            case 5:
                std::cout << "Bye!" << std::endl;
                exit(0);
                break;
            default:
                std::cout << "Invalid" << std::endl;
                break;
        }

    }
}

int main() {

    std::string main_str;
    std::vector<unsigned long long> history;

    init(main_str);
    encoder(main_str, history);

}
