#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <stdexcept>

#include <sqlite3.h>
#include <functional>
#include <mutex>
#include <vector>
#include <map>
#include <thread>

#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>

#include <websocketpp/config/asio.hpp>
#include <websocketpp/server.hpp>

#include <openssl/evp.h>

#include <cryptopp/aes.h>
#include <cryptopp/hex.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

typedef websocketpp::server<websocketpp::config::asio> server;

using websocketpp::connection_hdl;
using namespace CryptoPP;

sqlite3* db;
sqlite3_stmt* stmt = 0;
char *zErrMsg = 0;
int rc;

const std::string KEY_DIR = "test_key.bin";
const std::string SHARED_SECRET = "LMAODONE";

/* A 256 bit key */
const std::string key_data = "TvJHY58JNLeMtEimuA38xp2jvHaGYwvW";

std::string sha512(std::string message, std::string salt) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    char result[129];

    message += salt;

    md = EVP_get_digestbyname("sha512");
    if (md == NULL) {
            std::cout << "Unknown message digest: sha512" << std::endl;
        exit(1);
    }

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, message.substr(0, 128).c_str(), message.length());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    for (i = 0; i < md_len; i++) {
        sprintf(&result[i * 2], "%02x", md_value[i]);
    }

    return std::string("$6$") + salt + std::string("$") + std::string(result);
}

std::string aes256_encrypt(std::string plaintext, SecByteBlock key, SecByteBlock iv) {
    std::string cipher, encoded;

    try {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter adds padding
        //  as required. ECB and CBC Mode must be padded
        //  to the block size of the cipher.
        StringSource ss(plaintext, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    } catch( const CryptoPP::Exception& e ) {
        std::cerr << e.what() << std::endl;
    }

    std::cout << "cipher: " << cipher << std::endl;

    // Pretty print cipher text
    StringSource ss(cipher, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

std::string aes256_decrypt(std::string encoded, SecByteBlock key, SecByteBlock iv) {
    std::string recovered;

    try {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        // The StreamTransformationFilter removes
        //  padding as required.
        StringSource ss(encoded, true, new HexDecoder(new StreamTransformationFilter(d, new StringSink(recovered))));
    } catch( const CryptoPP::Exception& e ) {
        std::cerr << e.what() << std::endl;
    }

    return recovered;
}

void save_key(SecByteBlock key) {
    ArraySource as(key, sizeof(key), true, new FileSink("key.bin"));
}

class info {
    public:
        std::string nick;
        bool auth;

        info() {
            nick = "Guest";
            auth = false;
        }

        info(std::string name, bool authenticated) {
            nick = name;
            auth = authenticated;
        }

        ~info() {}
};

class message_server {
    public:
        SecByteBlock* key;

        message_server() {
            key = new SecByteBlock(AES::MAX_KEYLENGTH);
            FileSource fs(KEY_DIR.c_str(), true, new ArraySink(key->begin(), key->size()));
            m_server.init_asio();

            m_server.set_open_handler(bind(&message_server::on_open,this,std::placeholders::_1));
            m_server.set_message_handler(bind(&message_server::on_message,this,std::placeholders::_1, std::placeholders::_2));
            m_server.set_close_handler(bind(&message_server::on_close,this,std::placeholders::_1));
        }
    
        void on_message(connection_hdl hdl, server::message_ptr msg) {
            std::lock_guard<std::mutex> lock(m_mutex);

            std::string input = msg->get_payload();
            if (input == "-help") {
                std::string result = "Command List:\n";
                    result += "-help: Display this help text\n"; 
                    result += "-list: Displays the list of connected users\n";
                    result += "-register <name> <password>: Register with name and password\n";
                    result += "-login <name> <password>: Login with name and password\n";
                    result += "-msg <name> <message that can contain spaces>: Sends a message that gets encrypted.\n";
                    result += "-view <name>: Views all the received encrypted messages.";
                m_server.send(hdl, result, websocketpp::frame::opcode::text);
            } else if(input == "-list") {
                std::string result = "List of connected users: ";
                for (std::map<connection_hdl, info*>::iterator itr = con_map.begin(); itr != con_map.end(); itr++) {
                    result += ("\n" + itr->second->nick);
                }
                m_server.send(hdl, result, websocketpp::frame::opcode::text);
            } else if(boost::algorithm::istarts_with(input, "-register ")) {
                std::string text = input.substr(strlen("-register "));
                std::istringstream iss(text);
                std::vector<std::string> result {
                    std::istream_iterator<std::string>(iss), {}
                };
                if(result.size() != 2) {
                    // Incorrect parameters
                    m_server.send(hdl, "Incorrect number of parameters!", websocketpp::frame::opcode::text);
                } else {
                    // Checks if user name exists
                    std::string sql = "SELECT name FROM users WHERE name = ?1;";
                    sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);

                    // Bind parameters
                    sqlite3_bind_text(stmt, 1, result[0].c_str(), -1, SQLITE_STATIC);

                    rc = sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                    if (rc == SQLITE_ROW) {
                        // User already exists
                        m_server.send(hdl, "User name already exists!", websocketpp::frame::opcode::text);
                    } else {
                        // User does not exist. Will register
                        // #TODO Must use SHA 512 instead of plaintext (C++ openssl doesn't support bcrypt?)
                        sql = "INSERT INTO users(name, password) VALUES(?1, ?2);";
                        sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);

                        // Bind parameters
                        sqlite3_bind_text(stmt, 1, result[0].c_str(), -1, SQLITE_STATIC);
                        sqlite3_bind_text(stmt, 2, result[1].c_str(), -1, SQLITE_STATIC);

                        rc = sqlite3_step(stmt);
                        if (rc == SQLITE_DONE) {
                            m_server.send(hdl, "Registration complete!", websocketpp::frame::opcode::text);
                        } else {
                            m_server.send(hdl, "Error while registration!", websocketpp::frame::opcode::text);
                        }
                        sqlite3_finalize(stmt);
                    }
                }
            } else if(boost::algorithm::istarts_with(input, "-login ")) {
                std::string text = input.substr(strlen("-login "));
                std::istringstream iss(text);
                std::vector<std::string> result {
                    std::istream_iterator<std::string>(iss), {}
                };
                if(result.size() != 2) {
                    // Incorrect parameters
                    m_server.send(hdl, "Incorrect number of parameters!", websocketpp::frame::opcode::text);
                } else {
                    // Correct number of parameters
                    try {
                        bool isAuth = false;
                        isAuth = con_map.at(hdl)->auth;
                        if (isAuth) {
                            // Already logged in.
                            m_server.send(hdl, "Yo, you're already logged in -.-", websocketpp::frame::opcode::text);
                        } else {
                            // Not already logged and will attempt to login.
                            std::string sql = "SELECT name FROM users WHERE name = ?1 AND password = ?2;";
                            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);

                            // Bind parameters
                            sqlite3_bind_text(stmt, 1, result[0].c_str(), -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 2, result[1].c_str(), -1, SQLITE_STATIC);

                            rc = sqlite3_step(stmt);
                            if (rc == SQLITE_ROW) {
                                con_map.at(hdl)->nick = result[0];
                                con_map.at(hdl)->auth = true;
                                m_server.send(hdl, "Login complete!", websocketpp::frame::opcode::text);
                            } else {
                                m_server.send(hdl, "Wrong password!", websocketpp::frame::opcode::text);
                            }
                            sqlite3_finalize(stmt);
                        }
                    } catch (const std::out_of_range& e) {
                        std::cerr << "Out of Range error: " << e.what() << '\n';
                    }
                }
            } else if(boost::algorithm::istarts_with(input, "-msg ")) {
                try {
                    // Checks if user is authenticated
                    if(con_map.at(hdl)->auth) {
                        std::string receiver;
                        std::string message;

                        std::string text = input.substr(strlen("-msg "));
                        std::size_t i = text.find(" ");
                        if(i == std::string::npos) {
                            // Incorrect parameters
                            m_server.send(hdl, "Incorrect number of parameters!", websocketpp::frame::opcode::text);
                            return;
                        } else {
                            receiver = text.substr(0, i);
                        }

                        message = text.substr(i + 1);
                        if(message.length() > 0) {
                            // Contains a message

                            // Hashing the message with the given secret
                            AutoSeededRandomPool prng;
                            SecByteBlock iv(AES::BLOCKSIZE);
                            prng.GenerateBlock(iv, iv.size());

                            std::string hex_iv;
                            HexEncoder encoder; 
                            encoder.Attach(new StringSink(hex_iv));
                            encoder.Put(iv, iv.size());
                            encoder.MessageEnd(); 
                            std::cout << "sending hex_iv: " << hex_iv << std::endl;
                            
                            std::string cipher_text = aes256_encrypt(message, *key, iv);

                            // Sends the hashed message
                            std::string sql = "INSERT INTO messages(sender, receiver, hash, iv) VALUES(?1, ?2, ?3, ?4);";
                            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);

                            // Bind parameters
                            sqlite3_bind_text(stmt, 1, con_map.at(hdl)->nick.c_str(), -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 2, receiver.c_str(), -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 3, cipher_text.c_str(), -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 4, hex_iv.c_str(), -1, SQLITE_STATIC);

                            rc = sqlite3_step(stmt);
                            if (rc == SQLITE_DONE) {
                                m_server.send(hdl, "Sent message!", websocketpp::frame::opcode::text);
                            } else {
                                m_server.send(hdl, "Error while sending message!", websocketpp::frame::opcode::text);
                            }
                            sqlite3_finalize(stmt);
                        } else {
                            // Empty message!
                            m_server.send(hdl, "Cannot sent an empty message!", websocketpp::frame::opcode::text);
                        }
                    } else {
                        m_server.send(hdl, "You need to login first!", websocketpp::frame::opcode::text);
                    }
                } catch (const std::out_of_range& e) {
                    std::cerr << "Out of Range error: " << e.what() << '\n';
                }
            } else if(boost::algorithm::istarts_with(input, "-view ")) {
                try {
                    // Checks if user is authenticated
                    if(con_map.at(hdl)->auth) {
                        std::string sender = input.substr(strlen("-view "));
                        if(sender.length() > 0) {
                            // Reads hashed messages
                            std::string sql = "SELECT hash, iv FROM messages WHERE sender = ?1 AND receiver = ?2;";
                            sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);

                            // Bind parameters
                            sqlite3_bind_text(stmt, 1, sender.c_str(), -1, SQLITE_STATIC);
                            sqlite3_bind_text(stmt, 2, con_map.at(hdl)->nick.c_str(), -1, SQLITE_STATIC);

                            rc = sqlite3_step(stmt);
                            while (rc == SQLITE_ROW) {
                                // Reading a message

                                std::string cipher_text = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
                                std::string hex_iv = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
                                
                                std::cout << "received hex_iv: " << hex_iv << std::endl;

                                SecByteBlock iv(AES::BLOCKSIZE);
                                StringSource ivDecoder(hex_iv, true, new HexDecoder(new ArraySink(iv, iv.size())));

                                std::string plain_text = aes256_decrypt(cipher_text, *key, iv);
                                std::cout << "plain_text: " << plain_text << std::endl;
                                std::string server_message = std::string("PM from ") + sender + std::string(": ") + plain_text;

                                // Sending the decrypted message
                                m_server.send(hdl, server_message, websocketpp::frame::opcode::text);

                                rc = sqlite3_step(stmt);
                            }

                            sqlite3_finalize(stmt);
                        } else {
                            // Empty name!
                            m_server.send(hdl, "Enter a correcting user name!", websocketpp::frame::opcode::text);
                        }
                    } else {
                        m_server.send(hdl, "You need to login first!", websocketpp::frame::opcode::text);
                    }
                } catch (const std::out_of_range& e) {
                    std::cerr << "Out of Range error: " << e.what() << '\n';
                }
            } else {
                // Message is not a command
                try {
                    // Checks if user is authenticated
                    if(con_map.at(hdl)->auth) {
                        for (std::map<connection_hdl, info*>::iterator itr = con_map.begin(); itr != con_map.end(); itr++) {
                            std::string new_message = con_map.at(hdl)->nick + ": " + msg->get_payload();
                            m_server.send(itr->first, new_message, websocketpp::frame::opcode::text);
                        }
                    } else {
                        m_server.send(hdl, "You need to login first!", websocketpp::frame::opcode::text);
                    }
                } catch (const std::out_of_range& e) {
                    std::cerr << "Out of Range error: " << e.what() << '\n';
                }
            }
        }
        
        void on_open(connection_hdl hdl) {
            std::lock_guard<std::mutex> lock(m_mutex);

            con_map[(connection_hdl) hdl] = new info();
        }
        
        void on_close(connection_hdl hdl) {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            delete con_map[hdl];
            con_map.erase(hdl);
        }
        
        void listen_server_cmd() {
            while (1) {
                std::string input;
                std::cout << "Enter Command: ";
                std::getline(std::cin, input);

                if (input == "-exit") {
                    exit(0);
                } else if (input == "-help") {
                    std::cout
                    << "\nCommand List:\n"
                    << "-list: Displays the list of connected users\n"
                    << "-broadcast <message>: Broadcasts a message to all connected users\n"
                    << "-help: Display this help text\n"
                    << "-exit: Exit the program\n"
                    << std::endl;
                } else if (input == "-list") {
                    std::cout << "> List of connected users: " << std::endl;
                    for (std::map<connection_hdl, info*>::iterator itr = con_map.begin(); itr != con_map.end(); itr++) {
                        std::cout << itr->second->nick << std::endl;
                    }
                    std::cout << std::endl;

                } else if (boost::algorithm::istarts_with(input, "-broadcast ")) {
                    std::string text = input.substr(strlen("-broadcast "));

                    for (std::map<connection_hdl, info*>::iterator itr = con_map.begin(); itr != con_map.end(); itr++) {
                        m_server.send(itr->first, text, websocketpp::frame::opcode::text);
                    }
                } else {
                    std::cout << "> Unrecognized Command" << std::endl;
                }
            }
        }
        
        void run(uint16_t port) {
            std::cout << "Server On!" << std::endl;
            m_server.listen(port);
            m_server.start_accept();
            m_server.run();
        }

        ~message_server() {
            for (std::map<connection_hdl, info*>::iterator itr = con_map.begin(); itr != con_map.end(); itr++) {
                delete con_map[itr->first];
                con_map.erase(itr->first);
            }

            delete key;
        }

    private:
        std::map<connection_hdl, info*, std::owner_less<connection_hdl>> con_map;

        server m_server;
        std::mutex m_mutex;
};

int main() {
    // Initialize sqlite3 db    
    rc = sqlite3_open("server.db", &db);
    if(rc) {
        std::cout << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    };
 
    message_server server;
    std::thread t(std::bind(&message_server::listen_server_cmd, &server));
    server.run(8081);
    
    sqlite3_close(db);

    return 0;
}
