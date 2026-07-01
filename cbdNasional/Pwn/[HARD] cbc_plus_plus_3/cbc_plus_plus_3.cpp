

#include<iostream>
#include<string>

struct zzz_string { 
    unsigned long long length;
    char* data;
};

void init() {
}

void menu() {
    std::cout << "1. New zzz string" << std::endl;
    std::cout << "2. New std string" << std::endl;
    std::cout << "3. Move zzz string value to std string" << std::endl;
    std::cout << "4. Move std string value to zzz string" << std::endl;
    std::cout << "5. Print zzz string and std string" << std::endl;
    std::cout << "6. Exit" << std::endl;
    std::cout << "> ";
}

zzz_string z_str;
std::string *s_str;

int main() {

    init();

    int choice = 0, ind1 = 0, ind2 = 0;
    unsigned long long num = 0;

    while(1) {
        menu();
        std::cin >> choice;
        if(!std::cin.good()) break;
        switch(choice)  {
            case 1:
                std::cout << "Length: ";
                std::cin >> z_str.length;
                std::cin.ignore(1, '\n');
                if(z_str.data) delete z_str.data;
                z_str.data = new char[z_str.length + 1];
                std::cout << "Data: ";
                std::cin.read(z_str.data, z_str.length);
                std::cout << "Done" << std::endl;
                break;
            case 2:
                if(s_str) delete s_str;
                s_str = new std::string();
                std::cout << "Data: ";
                std::cin >> *s_str;
                std::cout << "Done" << std::endl;
                break;
            case 3:
                if(!z_str.data) break;
                if(!s_str) s_str = new std::string();
                *s_str = z_str.data;
                s_str->data()[z_str.length] = '\0';
                break;
            case 4:
                std::cout << "Unimplemented" << std::endl;
                break;
            case 5:
                if(z_str.data) {
                    std::cout << "zzz string: ";
                    std::cout.write(z_str.data, z_str.length);
                    std::cout << std::endl;
                }
                if(s_str) {
                    std::cout << "std string: " << *s_str << std::endl;
                }
                break;
            case 6:
                goto done;
            default:
                std::cout << "Invalid" << std::endl;
                break;
        }

    }
done:
    std::cout << "Bye!" << std::endl;
    return 0;
}
