#!/usr/bin/env bash

#
#Copyright Ziggurat Corp. 2017 All Rights Reserved.
#
#SPDX-License-Identifier: Apache-2.0
#

# Detecting whether can import the header file to render colorful cli output
if [ -f ./header.sh ]; then
 source ./header.sh
elif [ -f scripts/header.sh ]; then
 source scripts/header.sh
else
 alias echo_r="echo"
 alias echo_g="echo"
 alias echo_b="echo"
fi

CHANNEL_NAME="$1"
: ${CHANNEL_NAME:="mychannel"}
: ${TIMEOUT:="60"}
COUNTER=0
MAX_RETRY=5
add1 = ie43e15257182377bc957a99ce0ff65ff1c876a1b

ORDERER_CA=/opt/gopath/src/github.com/inklabsfoundation/inkchain/peer/crypto/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem

echo_b "Chaincode Path : "$CC_PATH
echo_b "Channel name : "$CHANNEL_NAME

verifyResult () {
    if [ $1 -ne 0 ] ; then
        echo_b "!!!!!!!!!!!!!!! "$2" !!!!!!!!!!!!!!!!"
        echo_r "================== ERROR !!! FAILED to execute MVE =================="
        echo
        exit 1
    fi
}

issueToken(){
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n ascc -c '{"Args":["registerAndIssueToken","'$1'","1000000000000000000000000000","9","iba1146d431d12cab51c3e0e106d6264b4b378f91"]}' >log.txt
    res=$?
    cat log.txt
    verifyResult $res "Issue a new token using ascc has Failed."
    echo_g "===================== A new token has been successfully issued======================= "
    echo
}

chaincodeQueryA () {
    echo_b "Attempting to Query account A's balance on peer "
    sleep 3
    peer chaincode query -C mychannel -n token -c '{"Args":["getBalance","iba1146d431d12cab51c3e0e106d6264b4b378f91","INK"]}' >log.txt
    res=$?
    cat log.txt
    verifyResult $res "query account A Failed."
}

addUser(){
    echo_b "Attempting to add user "
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["addUser","'$1'", "'$2'"]}' -i "1000000000" -z b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105 >log.txt
    res=$?
    cat log.txt
    verifyResult $res "add user has Failed."
    echo_g "===================== user add successfully======================= "
    echo
}

issueAuthorityToken(){
    echo_b "Attempting to Issue Authority Token "
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["issueAuthorityToken","'$1'"]}' -i "1000000000" -z b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105 #>log.txt
    res=$?
    #cat log.txt
    verifyResult $res "issue token has Failed."
    echo_g "===================== token issue successfully======================= "
    echo
}

deleteAuthorityToken(){
    echo_b "Attempting to Delete Authority Token "
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["deleteAuthorityToken","'$1'"]}' -i "1000000000" -z b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105 >log.txt
    res=$?
    cat log.txt
    verifyResult $res "delete token has Failed."
    echo_g "===================== token issue successfully======================= "
    echo
}

sendAuthorityTokenToUser(){
    echo_b "Attempting to Send Authority Token "
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["sendAuthorityTokenToUser","'$1'","'$2'"]}' -i "1000000000" -z b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105 >log.txt
    res=$?
    cat log.txt
    verifyResult $res "send authority token has Failed."
    echo_g "===================== token send successfully======================= "
    echo
}

withdrawAuthorityTokenFromUser(){
    echo_b "Attempting to Withdraw Authority Token "
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["withdrawAuthorityTokenFromUser","'$1'","'$2'"]}' -i "1000000000" -z b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105 >log.txt
    res=$?
    cat log.txt
    verifyResult $res "withdraw authority send token has Failed."
    echo_g "===================== token send successfully======================= "
    echo
}

userQuery () {
    echo_b "Attempting to Query User "
    sleep 5
    peer chaincode query -C mychannel -n network -c '{"Args":["queryUser","'$1'"]}' >log.txt
    res=$?
    cat log.txt
    verifyResult $res "query user failed."
}

queryAuthorityToken () {
    echo_b "Attempting to Query Authority Token "
    sleep 5
    peer chaincode query -C mychannel -n network -c '{"Args":["queryAuthorityToken"]}' >log.txt
    res=$?
    cat log.txt
    verifyResult $res "query token failed."
}

sendTokenToUser(){
    echo_b "Attempting to Send Token "
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["sendTokenToUser","'$1'","'$2'"]}' -i "1000000000" -z b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105 >log.txt
    res=$?
    cat log.txt
    verifyResult $res "send token has Failed."
    echo_g "===================== token send successfully======================= "
    echo
}

insertDataInfo(){
    echo_b "Attempting to Insert Data Info"
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["insertDataInfo","'$1'","'$2'","'$3'","'$4'"]}' -i "1000000000" -z b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105 >log.txt
    res=$?
    cat log.txt
    verifyResult $res "Failed to insert data info."
    echo_g "===================== insert data info successfully======================= "
    echo
}

insertAccessRule(){
    echo_b "Attempting to Insert Access Rule"
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["insertAccessRule","'$1'","'$2'"]}' -i "1000000000" -z b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105 >log.txt
    res=$?
    cat log.txt
    verifyResult $res "Failed to insert access rule."
    echo_g "===================== insert access rule successfully======================= "
    echo
}

getDataAccessPermission(){
    echo_b "Attempting to Get Data Access Permission"
    sleep 5
    peer chaincode invoke -o orderer.example.com:7050  --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA -C ${CHANNEL_NAME} -n network -c '{"Args":["getDataAccessPermission","'$1'","'$2'","'$3'","'$4'"]}' -i "1000000000" -z f62fb9b8c4e0273afe34ed1cd8164af0a8f638836b87d1543256fad46e6eba99 >log.txt
    res=$?
    cat log.txt
    verifyResult $res "Failed to get data access permission."
    echo_g "===================== get data access permission successfully======================= "
    echo
}

echo_b "=====================6.network invoke======================="
issueToken INK

echo_b "=====================7.query account======================="
chaincodeQueryA

echo_b "=====================8.add user======================="
addUser Alice ie43e15257182377bc957a99ce0ff65ff1c876a1b
#f62fb9b8c4e0273afe34ed1cd8164af0a8f638836b87d1543256fad46e6eba99
addUser Bob i3caf082aa98a78f4aafe1268cea4a4154a9b84f4
#74aceb1de660b91895ec2ea7251f10c0c5ca74f778723f2ebbdcd4c5dd542d11
#addUser Admin iba1146d431d12cab51c3e0e106d6264b4b378f91
#b17e3169bc49db69938ce3750c49a20015d28b3e4d512666f221d51de3db3105

echo_b "=====================9.issue token======================="
issueAuthorityToken MJGK
issueAuthorityToken MJMM
queryAuthorityToken
#deleteAuthorityToken Dongbu
#queryAuthorityToken
#issueAuthorityToken Dongbu
#queryAuthorityToken

echo_b "=====================9.send token======================="
sendTokenToUser ie43e15257182377bc957a99ce0ff65ff1c876a1b 1000000000000000
sendAuthorityTokenToUser ie43e15257182377bc957a99ce0ff65ff1c876a1b MJGK
sendAuthorityTokenToUser ie43e15257182377bc957a99ce0ff65ff1c876a1b MJMM
userQuery ie43e15257182377bc957a99ce0ff65ff1c876a1b
sendTokenToUser i3caf082aa98a78f4aafe1268cea4a4154a9b84f4 1000000000000000
userQuery i3caf082aa98a78f4aafe1268cea4a4154a9b84f4
##withdrawAuthorityTokenFromUser ie43e15257182377bc957a99ce0ff65ff1c876a1b MJGK


#sendTokenToUser i3caf082aa98a78f4aafe1268cea4a4154a9b84f4 0
#userQuery
##withdrawAuthorityTokenFromUser ie43e15257182377bc957a99ce0ff65ff1c876a1b Dongbu
##userQuery
##sendTokenToUser ie43e15257182377bc957a99ce0ff65ff1c876a1b 20
##userQuery

echo_b "=====================10.insert data info and rule====================="
insertDataInfo testHash testTag 30 i3caf082aa98a78f4aafe1268cea4a4154a9b84f4
insertAccessRule testTag 53
#53 d2b 00110101

echo_b "=====================11.get data access permission====================="
userQuery i3caf082aa98a78f4aafe1268cea4a4154a9b84f4
getDataAccessPermission testTag 30 i3caf082aa98a78f4aafe1268cea4a4154a9b84f4 5
#5 d2b 0101
userQuery i3caf082aa98a78f4aafe1268cea4a4154a9b84f4

echo
echo_g "=====================All GOOD, MVE Test completed ===================== "
echo
exit 0

