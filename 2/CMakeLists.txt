cmake_minimum_required(VERSION 3.17)

project(miniVPN)

find_package(OpenSSL REQUIRED)

add_executable(tlsServer tlsserver.c)
add_executable(tlsClient tlsclient.c)
add_executable(vpnServer vpnserver.c)
add_executable(vpnClient vpnclient.c)

target_link_libraries(tlsServer OpenSSL::Crypto OpenSSL::SSL crypt)
target_link_libraries(tlsClient OpenSSL::Crypto OpenSSL::SSL)
target_link_libraries(vpnServer)
target_link_libraries(vpnClient)
