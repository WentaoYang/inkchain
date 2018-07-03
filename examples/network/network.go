/*
Copyright Ziggurat Corp. 2018 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Network: chaincode for network project

package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/inklabsfoundation/inkchain/core/chaincode/shim"
	pb "github.com/inklabsfoundation/inkchain/protos/peer"
	"math/big"
	"strconv"
)

const (
	// invoke func name
	AddUser        		 			= "addUser"
	SendAuthorityTokenToUser   	  	= "sendAuthorityTokenToUser"
	WithdrawAuthorityTokenFromUser 	= "withdrawAuthorityTokenFromUser"
	QueryUser        	  			= "queryUser"
	IssueAuthorityToken       	  	= "issueAuthorityToken"
	DeleteAuthorityToken      	  	= "deleteAuthorityToken"
	QueryAuthorityToken       	  	= "queryAuthorityToken"

	SendTokenToUser					="sendTokenToUser"
	GetDataAccessPermission			="getDataAccessPermission"
	InsertDataInfo					="insertDataInfo"
	InsertAccessRule				="insertAccessRule"
)

var tokenToBit = map[string]uint32{
	"MJGK":		1,
	"MJMM":		2,
	"MJJI":		4,
	"MJJU":		8,
	"CJCM":		16,
	"CJCZ":		32,
	"CJSZ":		64,
	"JZLJ":		128,
	"JZHA":		256,
	"JZKJ":		512,
	"JZHU":		1024,
	"JZZJ":		2048,
	"ZQDB":		4096,
	"ZQNB":		8192,
	"ZQXB":		16384,
	"ZQBB":		32768,
	"ZQZB":		65536,
	"JWAA":		131072,
	"JWAB":		262144,
	"JWAC":		524288,
	"JWAD":		1048576,
	"JWAE":		2097152,
	"JWAF":		4194304,
	"JWAG":		8388608,
	"JWAH":		16777216,
	"JWAI":		33554432,
	"JWAJ":		67108864,
	"JWAK":		134217728,
}

// Is this allowed?
const (
	// internal func name
	CheckPermission		  = "checkPermission"
	CheckTokenExist		  = "checkTokenExist"
	InArray				  = "inArray"
)

// Only administrator can invoke these functions
const (
	AdminAddress 	= "iba1146d431d12cab51c3e0e106d6264b4b378f91"
	token_key 		= "token_key"
	BalanceType		= "INK"
	OperationBit	= 4
	OperationInt	= 15
)

// Demo chaincode for asset registering, querying and transferring
type networkChaincode struct {
}

type user struct {
	Name    		string   `json:"name"`				// user name
	AuthorityToken	[]string `json:"authoritytoken"`	// authority tokens owned by user
}

type userInfo struct {
	Name    		string   `json:"name"`				// user name
	AuthorityToken	[]string `json:"authoritytoken"`	// authority tokens owned by user
	Token			*big.Int `json:"token"`				// token amount （different from authority token）
}

type dataInfo struct {
	Hash    		string   `json:"hash"`				// data hash
	Tag				string 	 `json:"tag"`				// data security tag
	Price			*big.Int `json:"price"`				// data price
	Address			string   `json:"address"`			// address of data owner
}

type ruleInfo struct {
	Rule			[]string `json:"rule"`				// access rules
}

// ===================================================================================
// Main
// ===================================================================================
func main() {
	err := shim.Start(new(networkChaincode))
	if err != nil {
		fmt.Printf("Error starting networkChaincode: %s", err)
	}
}

// Init initializes chaincode
// ==================================================================================
func (t *networkChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Println("networkChaincode Init.")
	return shim.Success([]byte("Init success."))
}

// Invoke func
// ==================================================================================
func (t *networkChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	fmt.Println("networkChaincode Invoke.")
	function, args := stub.GetFunctionAndParameters()

	switch function {
	case AddUser:
		if len(args) != 2 {
			return shim.Error("Incorrect number of arguments. Expecting 2.")
		}
		// args[0]: user name
		// args[1]: user address
		// note: user address could be revealed from private key provided when invoking
		// Q: Is sender the admin or the user itself?
		return t.addUser(stub, args)

	case SendAuthorityTokenToUser:
		if len(args) != 2 {
			return shim.Error("Incorrect number of arguments. Expecting 2.")
		}
		// args[0]: user address
		// args[1]: token type
		return t.sendAuthorityTokenToUser(stub, args)

	case WithdrawAuthorityTokenFromUser:
		if len(args) != 2 {
			return shim.Error("Incorrect number of arguments. Expecting 2.")
		}
		// args[0]: user address
		// args[1]: token type
		return t.withdrawAuthorityTokenFromUser(stub, args)

	case QueryUser:
		if len(args) != 1 {
			return shim.Error("Incorrect number of arguments. Expecting 1.")
		}
		// args[0]: user address
		return t.queryUser(stub, args)

	case IssueAuthorityToken:
		if len(args) != 1 {
			return shim.Error("Incorrect number of arguments. Expecting 1.")
		}
		// args[0]: token type
		return t.issueAuthorityToken(stub, args)


	case DeleteAuthorityToken:
		if len(args) != 1 {
			return shim.Error("Incorrect number of arguments. Expecting 1.")
		}
		// args[0]: token type
		return t.deleteAuthorityToken(stub, args)

	case QueryAuthorityToken:
		if len(args) != 0 {
			return shim.Error("Incorrect number of arguments. Expecting 0.")
		}
		return t.queryAuthorityToken(stub, args)

	case SendTokenToUser:
		if len(args) != 2 {
			return shim.Error("Incorrect number of arguments. Expecting 2.")
		}
		// args[0]: to address
		// args[1]: token amount
		return t.sendTokenToUser(stub, args)

	case GetDataAccessPermission:
		if len(args) != 4 {
			return shim.Error("Incorrect number of arguments. Expecting 4.")
		}
		// args[0]: data tag
		// args[1]: data price
		// args[2]: data onwer's address
		// args[3]: required operation
		return t.getDataAccessPermission(stub, args)

	case InsertDataInfo:
		if len(args) != 4 {
			return shim.Error("Incorrect number of arguments. Expecting 4.")
		}
		// args[0]: data hash
		// args[1]: data tag
		// args[2]: data price
		// args[3]: data onwer's address
		return t.insertDataInfo(stub, args)

	case InsertAccessRule:
		if len(args) < 2 {
			return shim.Error("Incorrect number of arguments. Expecting 4.")
		}
		// args[0]: tag
		// args[1]: rule
		return t.insertAccessRule(stub, args)

	}

	return shim.Error("Invalid invoke function name.")
}

// =============================
// addUser: Register a new user
// =============================
func (t *networkChaincode) addUser(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var new_name string
	var new_address string
	var err error

	new_name = args[0]
	new_address = strings.ToLower(args[1])

	// get invoker's address and check permission
	sender_add, err := stub.GetSender()
	if err != nil {
		return shim.Error("Fail to reveal invoker's address.")
	}
	sender_add = strings.ToLower(sender_add)
	if checkPermission(sender_add) == false {
		return shim.Error("No permissions invoking.")
	}

	// check if user exists
	user_key := new_address
	userAsBytes, err := stub.GetState(user_key)
	if err != nil {
		return shim.Error("Fail to get user: " + err.Error())
	} else if userAsBytes != nil {
		fmt.Println("This user address already exists: " + new_address)
		return shim.Error("This user address already exists: " + new_address)
	}

	// register user
	user := &user{new_name, []string{}}
	userJSONasBytes, err := json.Marshal(user)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(user_key, userJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

//	return shim.Success([]byte("User register success."))
	return shim.Success(userJSONasBytes)
}

// ==========================================
// sendTokenToUser: Send token to a user
// ==========================================
func (t *networkChaincode) sendAuthorityTokenToUser(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// args[0]: user address
	// args[1]: token type
	var user_address string
	var token_type string
	var err error

	user_address = strings.ToLower(args[0])
	token_type = args[1]

	// get invoker's address and check permission
	sender_add, err := stub.GetSender()
	if err != nil {
		return shim.Error("Fail to reveal invoker's address.")
	}
	sender_add = strings.ToLower(sender_add)
	if checkPermission(sender_add) == false {
		return shim.Error("No permissions invoking.")
	}

	// check if user exists
	user_key := user_address
	userAsBytes, err := stub.GetState(user_key)
	if err != nil {
		return shim.Error("Fail to get user: " + err.Error())
	} else if userAsBytes == nil {
		fmt.Println("No such user address: " + user_address)
		return shim.Error("No such user address: " + user_address)
	}

	// check if token exists
	tokenAsBytes, err := stub.GetState(token_key)
	if err != nil {
		return shim.Error("Fail to get user: " + err.Error())
	}
	if checkTokenExist(tokenAsBytes, token_type) == false {
		fmt.Println("No such token type" + token_type)
		return shim.Error("No such token type: " + token_type)
	}

	// send token to user
	var userToWithdrawToken user
	err = json.Unmarshal(userAsBytes, &userToWithdrawToken)
	if err != nil {
		jsonResp := "{\"Error\":\"Json Unmarshal failed, " + err.Error() + "\"}"
		return shim.Error(jsonResp)
	}
	index:= inArray(userToWithdrawToken.AuthorityToken,token_type)
	if index != -1 {
		return shim.Error("User: " + user_address + "already has this token: " + token_type)
	}
	var userToSendToken user
	err = json.Unmarshal(userAsBytes, &userToSendToken)
	if err != nil {
		return shim.Error(err.Error())
	}
	userToSendToken.AuthorityToken = append(userToSendToken.AuthorityToken, token_type)

	updatedUserAsBytes, err := json.Marshal(userToSendToken)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(user_key, updatedUserAsBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success([]byte("Send success."))
}

// ==========================================
// sendTokenToUser: Send token to a user
// ==========================================
func (t *networkChaincode) withdrawAuthorityTokenFromUser(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// args[0]: user address
	// args[1]: token type
	var user_address string
	var token_type string
	var err error

	user_address = strings.ToLower(args[0])
	token_type = args[1]

	// get invoker's address and check permission
	sender_add, err := stub.GetSender()
	if err != nil {
		return shim.Error("Fail to reveal invoker's address.")
	}
	sender_add = strings.ToLower(sender_add)
	if checkPermission(sender_add) == false {
		return shim.Error("No permissions invoking.")
	}

	// check if user exists
	user_key := user_address
	userAsBytes, err := stub.GetState(user_key)
	if err != nil {
		return shim.Error("Fail to get user: " + err.Error())
	} else if userAsBytes == nil {
		fmt.Println("No such user address: " + user_address)
		return shim.Error("No such user address: " + user_address)
	}

	// check if token exists
	tokenAsBytes, err := stub.GetState(token_key)
	if err != nil {
		return shim.Error("Fail to get user: " + err.Error())
	}
	if checkTokenExist(tokenAsBytes, token_type) == false {
		fmt.Println("No such token type" + token_type)
		return shim.Error("No such token type: " + token_type)
	}

	// withdraw token from user
	var userToWithdrawToken user
	err = json.Unmarshal(userAsBytes, &userToWithdrawToken)
	if err != nil {
		return shim.Error(err.Error())
	}

	index:= inArray(userToWithdrawToken.AuthorityToken,token_type)
	if index == -1 {
		return shim.Error("User: " + user_address + "doesn't have this token: " + token_type)
	}

	userToWithdrawToken.AuthorityToken = append(userToWithdrawToken.AuthorityToken[:index],userToWithdrawToken.AuthorityToken[index+1:]... )

	updatedUserAsBytes, err := json.Marshal(userToWithdrawToken)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(user_key, updatedUserAsBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success([]byte("Withdraw success."))
}

// ==========================================
// queryUser: query the information of a user
// ==========================================
func (t *networkChaincode) queryUser(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	user_address := strings.ToLower(args[0])
	user_key := user_address

	// get user name and authority token
	var userWithAuthorityToken user
	userAsBytes, err := stub.GetState(user_key)
	if err != nil {
		return shim.Error("Fail to get user: " + err.Error())
	}
	if userAsBytes == nil {
		fmt.Println("This user doesn't exist: " + user_address)
		return shim.Error("This user doesn't exist: " + user_address)
	}
	err = json.Unmarshal(userAsBytes, &userWithAuthorityToken)
	if err != nil {
		jsonResp := "{\"Error\":\"Json Unmarshal failed, " + err.Error() + "\"}"
		return shim.Error(jsonResp)
	}

	// get user token amount
	var userToBeQueried userInfo
	var balanceAmount *big.Int
	// Get the state from the ledger
	account, err := stub.GetAccount(user_address)
	if err != nil {
		return shim.Error(err.Error())
	//	return shim.Error("user address does not exists: " + user_address)
	}
	if account == nil || account.Balance[BalanceType] == nil {
		balanceAmount, ok := balanceAmount.SetString("0", 10)
		userToBeQueried.Token = balanceAmount
		if !ok {
			return shim.Error("Expecting integer value for token amount.")
		}
	} else {
		balanceAmount = account.Balance[BalanceType]
		userToBeQueried.Token = balanceAmount
	}
	userToBeQueried.Name = userWithAuthorityToken.Name
	userToBeQueried.AuthorityToken = userWithAuthorityToken.AuthorityToken
	userToBeQueriedAsBytes, err := json.Marshal(userToBeQueried)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(userToBeQueriedAsBytes)
}

// =============================================
// issueToken: issue a new token
// =============================================
func (t *networkChaincode) issueAuthorityToken(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// args[0]: token type
	var newToken string
	var err error

	newToken = args[0]

	// get invoker's address and check permission
	sender_add, err := stub.GetSender()
	if err != nil {
		return shim.Error("Fail to reveal invoker's address.")
	}
	sender_add = strings.ToLower(sender_add)
	if checkPermission(sender_add) == false {
		return shim.Error("No permissions invoking.")
	}

	// check if token exists
	tokenAsBytes, err := stub.GetState(token_key)
	if err != nil {
		return shim.Error("Fail to get token: " + err.Error())
	}

	var tokenBank []string
	if tokenAsBytes != nil {
		err = json.Unmarshal(tokenAsBytes, &tokenBank)
		if err != nil {
			return shim.Error(err.Error())
		}
		if checkTokenExist(tokenAsBytes, newToken) == true {
			fmt.Println("This token has already issued" + newToken)
			return shim.Error("This token has already issued: " + newToken)
		}
	}

	// issue token
	tokenBank = append(tokenBank, newToken)
	updatedTokenBank, err := json.Marshal(tokenBank)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(token_key, updatedTokenBank)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success([]byte("Authority token issue success."))
}

// =============================================
// deleteToken: issue a new token
//
// NOTICE: this function only delete certain type of token from the token bank,
//         and won't delete this token from each individual user
// =============================================
func (t *networkChaincode) deleteAuthorityToken(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// args[0]: token type
	var delToken string
	var err error
	delToken = args[0]

	// get invoker's address and check permission
	sender_add, err := stub.GetSender()
	if err != nil {
		return shim.Error("Fail to reveal invoker's address.")
	}
	sender_add = strings.ToLower(sender_add)
	if checkPermission(sender_add) == false {
		return shim.Error("No permissions invoking.")
	}

	// check if token exists
	tokenAsBytes, err := stub.GetState(token_key)
	if err != nil {
		return shim.Error("Fail to get token: " + err.Error())
	}
	if checkTokenExist(tokenAsBytes, delToken) == false {
		fmt.Println("This token doesn't exit:" + delToken)
		return shim.Error("This token doesn't exit: " + delToken)
	}

	// delete token
	var tokenBank []string
	err = json.Unmarshal(tokenAsBytes, &tokenBank)
	if err != nil {
		return shim.Error(err.Error())
	}
	index:= inArray(tokenBank,delToken)
	if index == -1 {
		return shim.Error("This token doesn't exit: " + delToken)
	}
	tokenBank = append(tokenBank[:index],tokenBank[index+1:]... )
	updatedTokenBank, err := json.Marshal(tokenBank)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(token_key, updatedTokenBank)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success([]byte("Authority token delete success."))

}

// =============================================
// queryToken: query the information of all issued tokens
// =============================================
func (t *networkChaincode) queryAuthorityToken(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	tokenAsBytes, err := stub.GetState(token_key)
	if err != nil {
		return shim.Error("Fail to get token: " + err.Error())
	}
	if tokenAsBytes == nil {
		fmt.Println("No authority token has been issued")
		return shim.Error("No authority token has been issued")
	}

	return shim.Success(tokenAsBytes)
}

// =============================================
// sendTokenToUser: send token to specific user address
// =============================================
func (t *networkChaincode) sendTokenToUser(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// args[0]: to address
	// args[1]: token amount
	var toAddress 	string
	var tokenAmount *big.Int
	var err			error

	tokenAmount = big.NewInt(0)
	toAddress 		 = strings.ToLower(args[0])
	tokenAmount, ok := tokenAmount.SetString(args[1],10)
	//fmt.Println(toAddress)
	//fmt.Println(tokenAmount)
	if !ok {
		return shim.Error("Expecting integer value for token amount.")
	}

	err = stub.Transfer(toAddress, BalanceType, tokenAmount)
	if err != nil {
		return shim.Error("Error when making transfer。")
	}

	return shim.Success([]byte("Token send success."))
}

func (t *networkChaincode) getDataAccessPermission(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// args[0]: data tag
	// args[1]: data price
	// args[2]: data onwer's address
	// args[3]: required operation
	var dataTag				string
	var dataPrice   		*big.Int
	var ownerAddress		string
	var requiredOperation 	int
	var err					error

	dataTag   = args[0]
	dataPrice = big.NewInt(0)
	dataPrice, ok := dataPrice.SetString(args[1],10)
	if !ok {
		return shim.Error("Expecting integer value for token amount.")
	}

	ownerAddress = strings.ToLower(args[2])
	requiredOperation, err = strconv.Atoi(args[3])
	if err != nil {
		return shim.Error("4th argument must be a numeric string")
	}

	// get buyer (invoker) address
	buyerAddress, err := stub.GetSender()
	if err != nil {
		return shim.Error("Fail to reveal invoker's address.")
	}
	buyerAddress = strings.ToLower(buyerAddress)

	// Get Rule
	var accessRule  ruleInfo
	var rule_key	string
	rule_key = dataTag
	ruleAsBytes, err := stub.GetState(rule_key)
	if err != nil {
		return shim.Error("Fail to get access rule: " + err.Error())
	}
	if ruleAsBytes == nil {
		fmt.Println("Rule for this data tag doesn't exist: " + dataTag)
		return shim.Error("Rule for this data tag doesn't exist: " + dataTag)
	}
	err = json.Unmarshal(ruleAsBytes, &accessRule)
	if err != nil {
		jsonResp := "{\"Error\":\"Json Unmarshal failed, " + err.Error() + "\"}"
		return shim.Error(jsonResp)
	}

	// Get Balance
	var balanceAmount *big.Int
	balanceAmount = big.NewInt(0)

	account, err := stub.GetAccount(buyerAddress)
	if err != nil {
		return shim.Error(err.Error())
		//	return shim.Error("user address does not exists: " + user_address)
	}
	if account == nil || account.Balance[BalanceType] == nil {
		balanceAmount, ok = balanceAmount.SetString("0", 10)
		if !ok {
			return shim.Error("Expecting integer value for token amount.")
		}
	} else {
		balanceAmount = account.Balance[BalanceType]
	}
	if balanceAmount.Cmp(dataPrice) == -1  {
		return shim.Error("Buyer can't afford to buy the data.")
	}

	// Get buyer's authority token
	buyer_key := buyerAddress

	var buyer user
	buyerAsBytes, err := stub.GetState(buyer_key)
	if err != nil {
		return shim.Error("Fail to get buyer: " + err.Error())
	}
	if buyerAsBytes == nil {
		fmt.Println("This buyer doesn't exist: " + buyerAddress)
		return shim.Error("This buyer doesn't exist: " + buyerAddress)
	}
	err = json.Unmarshal(buyerAsBytes, &buyer)
	if err != nil {
		jsonResp := "{\"Error\":\"Json Unmarshal failed, " + err.Error() + "\"}"
		return shim.Error(jsonResp)
	}

	// Permission Check
	var buyAuthorityToken	uint32
	var buyOperation		uint32
	var ruleToken			uint32
	var ruleOperation		uint32

	buyAuthorityToken = 0
	for i := 0; i < len(buyer.AuthorityToken); i++ {
		buyAuthorityToken = buyAuthorityToken + tokenToBit[buyer.AuthorityToken[i]]
	}
	buyOperation = uint32(requiredOperation)

	for i := 0; i < len(accessRule.Rule); i++ {
		ruleBit, err := strconv.Atoi(accessRule.Rule[i])
		if err != nil {
			return shim.Error("Access rule must be a numeric string")
		}

		ruleToken = uint32(ruleBit) >> OperationBit
		ruleOperation  = uint32(ruleBit) & OperationInt

		if ((buyAuthorityToken & ruleToken) == ruleToken) && ((buyOperation & ruleOperation) == buyOperation) {
			// transfer
			err = stub.Transfer(ownerAddress, BalanceType, dataPrice)
			if err != nil {
				return shim.Error("Error when making transfer。")
			}
			return shim.Success([]byte("Permitted."))
		}

	}

	return shim.Error("Access denied")
}

// =============================================
// update data
// =============================================
func (t *networkChaincode) insertDataInfo(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	// args[0]: data hash
	// args[1]: data tag
	// args[2]: data price
	// args[3]: data onwer's address
	var dataHash 			string
	var dataTag 			string
	var dataPrice 			*big.Int
	var dataOnwerAddress	string
	var err error

	dataHash  = args[0]
	dataTag   = args[1]
	dataPrice = big.NewInt(0)
	dataPrice, ok := dataPrice.SetString(args[2],10)
	if !ok {
		return shim.Error("Expecting integer value for token amount.")
	}
	dataOnwerAddress = strings.ToLower(args[3])

	// get invoker's address and check permission
	sender_add, err := stub.GetSender()
	if err != nil {
		return shim.Error("Fail to reveal invoker's address.")
	}
	sender_add = strings.ToLower(sender_add)
	if checkPermission(sender_add) == false {
		return shim.Error("No permissions invoking.")
	}

	// check if data exists
	data_key := dataHash
	dataAsBytes, err := stub.GetState(data_key)
	if err != nil {
		return shim.Error("Fail to get data: " + err.Error())
	} else if dataAsBytes != nil {
		fmt.Println("This data hash already exists: " + dataHash)
		return shim.Error("This data hash already exists: " + dataHash)
	}

	// Insert data info
	dataInfo := &dataInfo{dataHash, dataTag, dataPrice, dataOnwerAddress}
	dataJSONasBytes, err := json.Marshal(dataInfo)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(data_key, dataJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success([]byte("Insert data info success."))

}

// =============================================
// update data access rules
// =============================================
func (t *networkChaincode) insertAccessRule(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	// args[0]: tag
	// args[1～n]: rule
	var dataTag 		string
	var accessRule		ruleInfo
	var err 			error

	// get args
	dataTag    = args[0]
	for i := 1; i < len(args); i++ {
		accessRule.Rule = append(accessRule.Rule, args[i])
	}
	// get invoker's address and check permission
	sender_add, err := stub.GetSender()
	if err != nil {
		return shim.Error("Fail to reveal invoker's address.")
	}
	sender_add = strings.ToLower(sender_add)
	if checkPermission(sender_add) == false {
		return shim.Error("No permissions invoking.")
	}

	// store in database
	var rule_key	string

	rule_key = dataTag
	ruleAsBytes, err := stub.GetState(rule_key)
	if err != nil {
		return shim.Error("Fail to get data: " + err.Error())
	} else if ruleAsBytes != nil {
		fmt.Println("Rule for this data tag already exists: " + dataTag)
		return shim.Error("Rule for this data tag already exists: " + dataTag)
	}

	// Insert access rule
	ruleJSONasBytes, err := json.Marshal(accessRule)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState(rule_key, ruleJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success([]byte("Insert access rule success."))

}

// =============================================
// For administrator-only operations
// =============================================
func checkPermission(args string) bool {
	if args == AdminAddress {
		return true
	}
	return false
}

// =============================================
// whether this token exists
// =============================================
func checkTokenExist(tokenAsBytes []byte, tokenToCheck string) bool {
	var tokenBank []string
	var err error
	if tokenAsBytes != nil {
		err = json.Unmarshal(tokenAsBytes, &tokenBank)
		if err != nil {
			return false
		}
		for i := 0; i < len(tokenBank); i++ {
			if  tokenBank[i] == tokenToCheck {
				return true
			}
		}
	}
	return false
}

// ========================================================================
// inArray: check if the user already has this type of token
// ========================================================================
func inArray(stringArray []string, stringToCheck string) int {
	for i := 0; i < len(stringArray); i++ {
		if  stringArray[i] == stringToCheck {
			return i
		}
	}
	return -1
}