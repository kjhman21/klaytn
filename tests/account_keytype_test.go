// Copyright 2019 The klaytn Authors
// This file is part of the klaytn library.
//
// The klaytn library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The klaytn library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the klaytn library. If not, see <http://www.gnu.org/licenses/>.

package tests

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/klaytn/klaytn/rlp"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/klaytn/klaytn/accounts/abi"
	"github.com/klaytn/klaytn/blockchain"
	"github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/blockchain/types/accountkey"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/common/profile"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/klaytn/kerrors"
	"github.com/klaytn/klaytn/params"
	"github.com/stretchr/testify/assert"
)

// createDefaultAccount creates a default account with a specific account key type.
func createDefaultAccount(accountKeyType accountkey.AccountKeyType) (*TestAccountType, error) {
	var err error

	// prepare  keys
	keys := genTestKeys(3)
	weights := []uint{1, 1, 1}
	weightedKeys := make(accountkey.WeightedPublicKeys, 3)
	threshold := uint(2)

	for i := range keys {
		weightedKeys[i] = accountkey.NewWeightedPublicKey(weights[i], (*accountkey.PublicKeySerializable)(&keys[i].PublicKey))
	}

	// a role-based key
	roleAccKey := accountkey.AccountKeyRoleBased{
		accountkey.NewAccountKeyPublicWithValue(&keys[accountkey.RoleTransaction].PublicKey),
		accountkey.NewAccountKeyPublicWithValue(&keys[accountkey.RoleAccountUpdate].PublicKey),
		accountkey.NewAccountKeyPublicWithValue(&keys[accountkey.RoleFeePayer].PublicKey),
	}

	// default account setting
	account := &TestAccountType{
		Addr:   crypto.PubkeyToAddress(keys[0].PublicKey), // default
		Keys:   []*ecdsa.PrivateKey{keys[0]},              // default
		Nonce:  uint64(0),                                 // default
		AccKey: nil,
	}

	// set an account key and a private key
	switch accountKeyType {
	case accountkey.AccountKeyTypeNil:
		account.AccKey, err = accountkey.NewAccountKey(accountKeyType)
	case accountkey.AccountKeyTypeLegacy:
		account.AccKey, err = accountkey.NewAccountKey(accountKeyType)
	case accountkey.AccountKeyTypePublic:
		account.AccKey = accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey)
	case accountkey.AccountKeyTypeFail:
		account.AccKey, err = accountkey.NewAccountKey(accountKeyType)
	case accountkey.AccountKeyTypeWeightedMultiSig:
		account.Keys = keys
		account.AccKey = accountkey.NewAccountKeyWeightedMultiSigWithValues(threshold, weightedKeys)
	case accountkey.AccountKeyTypeRoleBased:
		account.Keys = keys
		account.AccKey = accountkey.NewAccountKeyRoleBasedWithValues(roleAccKey)
	default:
		return nil, kerrors.ErrDifferentAccountKeyType
	}
	if err != nil {
		return nil, err
	}

	return account, err
}

// generateDefaultTx returns a Tx with default values of txTypes.
// If txType is a kind of account update, it will return an account to update.
// Otherwise, it will return (tx, nil, nil).
// For contract execution Txs, TxValueKeyTo value is set to "contract" as a default.
// The address "contact" should exist before calling this function.
func generateDefaultTx(sender *TestAccountType, recipient *TestAccountType, txType types.TxType, contractAddr common.Address) (*types.Transaction, *TestAccountType, error) {
	gasPrice := new(big.Int).SetUint64(25 * params.Ston)
	gasLimit := uint64(10000000)
	amount := new(big.Int).SetUint64(1)

	// generate a new account for account creation/update Txs or contract deploy Txs
	senderAccType := accountkey.AccountKeyTypeLegacy
	if sender.AccKey != nil {
		senderAccType = sender.AccKey.Type()
	}
	newAcc, err := createDefaultAccount(senderAccType)
	if err != nil {
		return nil, nil, err
	}

	// Smart contract data for TxTypeSmartContractDeploy, TxTypeSmartContractExecution Txs
	var code string
	var abiStr string

	if isCompilerAvailable() {
		filename := string("../contracts/reward/contract/KlaytnReward.sol")
		codes, abistrings := compileSolidity(filename)
		code = codes[0]
		abiStr = abistrings[0]
	} else {
		// Falling back to use compiled code.
		code = "0x608060405234801561001057600080fd5b506101de806100206000396000f3006080604052600436106100615763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416631a39d8ef81146100805780636353586b146100a757806370a08231146100ca578063fd6b7ef8146100f8575b3360009081526001602052604081208054349081019091558154019055005b34801561008c57600080fd5b5061009561010d565b60408051918252519081900360200190f35b6100c873ffffffffffffffffffffffffffffffffffffffff60043516610113565b005b3480156100d657600080fd5b5061009573ffffffffffffffffffffffffffffffffffffffff60043516610147565b34801561010457600080fd5b506100c8610159565b60005481565b73ffffffffffffffffffffffffffffffffffffffff1660009081526001602052604081208054349081019091558154019055565b60016020526000908152604090205481565b336000908152600160205260408120805490829055908111156101af57604051339082156108fc029083906000818181858888f193505050501561019c576101af565b3360009081526001602052604090208190555b505600a165627a7a72305820627ca46bb09478a015762806cc00c431230501118c7c26c30ac58c4e09e51c4f0029"
		abiStr = `[{"constant":true,"inputs":[],"name":"totalAmount","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"receiver","type":"address"}],"name":"reward","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[],"name":"safeWithdrawal","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"},{"payable":true,"stateMutability":"payable","type":"fallback"}]`
	}

	abii, err := abi.JSON(strings.NewReader(string(abiStr)))
	if err != nil {
		return nil, nil, err
	}

	dataABI, err := abii.Pack("reward", recipient.Addr)
	if err != nil {
		return nil, nil, err
	}

	// generate a legacy tx
	if txType == types.TxTypeLegacyTransaction {
		tx := types.NewTransaction(sender.Nonce, recipient.Addr, amount, gasLimit, gasPrice, []byte{})
		return tx, nil, nil
	}

	// Default valuesMap setting
	amountZero := new(big.Int).SetUint64(0)
	ratio := types.FeeRatio(30)
	dataMemo := []byte("hello")
	dataAnchor := []byte{0x11, 0x22}
	dataCode := common.FromHex(code)
	values := map[types.TxValueKeyType]interface{}{}

	switch txType {
	case types.TxTypeValueTransfer:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = recipient.Addr
		values[types.TxValueKeyAmount] = amount
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
	case types.TxTypeFeeDelegatedValueTransfer:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = recipient.Addr
		values[types.TxValueKeyAmount] = amount
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyFeePayer] = recipient.Addr
	case types.TxTypeFeeDelegatedValueTransferWithRatio:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = recipient.Addr
		values[types.TxValueKeyAmount] = amount
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyFeePayer] = recipient.Addr
		values[types.TxValueKeyFeeRatioOfFeePayer] = ratio
	case types.TxTypeValueTransferMemo:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = recipient.Addr
		values[types.TxValueKeyAmount] = amount
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyData] = dataMemo
	case types.TxTypeFeeDelegatedValueTransferMemo:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = recipient.Addr
		values[types.TxValueKeyAmount] = amount
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyData] = dataMemo
		values[types.TxValueKeyFeePayer] = recipient.Addr
	case types.TxTypeFeeDelegatedValueTransferMemoWithRatio:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = recipient.Addr
		values[types.TxValueKeyAmount] = amount
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyData] = dataMemo
		values[types.TxValueKeyFeePayer] = recipient.Addr
		values[types.TxValueKeyFeeRatioOfFeePayer] = ratio
	case types.TxTypeAccountUpdate:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyAccountKey] = newAcc.AccKey
	case types.TxTypeFeeDelegatedAccountUpdate:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyAccountKey] = newAcc.AccKey
		values[types.TxValueKeyFeePayer] = recipient.Addr
	case types.TxTypeFeeDelegatedAccountUpdateWithRatio:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyAccountKey] = newAcc.AccKey
		values[types.TxValueKeyFeePayer] = recipient.Addr
		values[types.TxValueKeyFeeRatioOfFeePayer] = ratio
	case types.TxTypeSmartContractDeploy:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = (*common.Address)(nil)
		values[types.TxValueKeyAmount] = amountZero
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = amountZero
		values[types.TxValueKeyData] = dataCode
		values[types.TxValueKeyHumanReadable] = false
		values[types.TxValueKeyCodeFormat] = params.CodeFormatEVM
	case types.TxTypeFeeDelegatedSmartContractDeploy:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = (*common.Address)(nil)
		values[types.TxValueKeyAmount] = amountZero
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = amountZero
		values[types.TxValueKeyData] = dataCode
		values[types.TxValueKeyHumanReadable] = false
		values[types.TxValueKeyFeePayer] = recipient.Addr
		values[types.TxValueKeyCodeFormat] = params.CodeFormatEVM
	case types.TxTypeFeeDelegatedSmartContractDeployWithRatio:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = (*common.Address)(nil)
		values[types.TxValueKeyAmount] = amountZero
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = amountZero
		values[types.TxValueKeyData] = dataCode
		values[types.TxValueKeyHumanReadable] = false
		values[types.TxValueKeyFeePayer] = recipient.Addr
		values[types.TxValueKeyFeeRatioOfFeePayer] = ratio
		values[types.TxValueKeyCodeFormat] = params.CodeFormatEVM
	case types.TxTypeSmartContractExecution:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = contractAddr
		values[types.TxValueKeyAmount] = amountZero
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = amountZero
		values[types.TxValueKeyData] = dataABI
	case types.TxTypeFeeDelegatedSmartContractExecution:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = contractAddr
		values[types.TxValueKeyAmount] = amountZero
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = amountZero
		values[types.TxValueKeyData] = dataABI
		values[types.TxValueKeyFeePayer] = recipient.Addr
	case types.TxTypeFeeDelegatedSmartContractExecutionWithRatio:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyTo] = contractAddr
		values[types.TxValueKeyAmount] = amountZero
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = amountZero
		values[types.TxValueKeyData] = dataABI
		values[types.TxValueKeyFeePayer] = recipient.Addr
		values[types.TxValueKeyFeeRatioOfFeePayer] = ratio
	case types.TxTypeCancel:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
	case types.TxTypeFeeDelegatedCancel:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyFeePayer] = recipient.Addr
	case types.TxTypeFeeDelegatedCancelWithRatio:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyFeePayer] = recipient.Addr
		values[types.TxValueKeyFeeRatioOfFeePayer] = ratio
	case types.TxTypeChainDataAnchoring:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyAnchoredData] = dataAnchor
	case types.TxTypeFeeDelegatedChainDataAnchoring:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyAnchoredData] = dataAnchor
		values[types.TxValueKeyFeePayer] = recipient.Addr
	case types.TxTypeFeeDelegatedChainDataAnchoringWithRatio:
		values[types.TxValueKeyNonce] = sender.Nonce
		values[types.TxValueKeyFrom] = sender.Addr
		values[types.TxValueKeyGasLimit] = gasLimit
		values[types.TxValueKeyGasPrice] = gasPrice
		values[types.TxValueKeyAnchoredData] = dataAnchor
		values[types.TxValueKeyFeePayer] = recipient.Addr
		values[types.TxValueKeyFeeRatioOfFeePayer] = ratio
	}

	tx, err := types.NewTransactionWithMap(txType, values)
	if err != nil {
		return nil, nil, err
	}

	// the function returns an updated sender account for account update Txs
	if txType.IsAccountUpdate() {
		// For the account having a legacy key, its private key will not be updated since it is coupled with its address.
		if newAcc.AccKey.Type().IsLegacyAccountKey() {
			newAcc.Keys = sender.Keys
		}
		newAcc.Addr = sender.Addr
		newAcc.Nonce = sender.Nonce
		return tx, newAcc, err
	}

	return tx, nil, err
}

// expectedTestResultForDefaultTx returns expected validity of tx which generated from (accountKeyType, txType) pair.
func expectedTestResultForDefaultTx(accountKeyType accountkey.AccountKeyType, txType types.TxType) error {
	switch accountKeyType {
	//case accountkey.AccountKeyTypeNil:                     // not supported type
	case accountkey.AccountKeyTypeFail:
		if txType.IsAccountUpdate() {
			return kerrors.ErrAccountKeyFailNotUpdatable
		}
		return types.ErrInvalidSigSender
	}
	return nil
}

func signTxWithVariousKeyTypes(signer types.EIP155Signer, tx *types.Transaction, sender *TestAccountType) (*types.Transaction, error) {
	var err error
	txType := tx.Type()
	accKeyType := sender.AccKey.Type()

	if accKeyType == accountkey.AccountKeyTypeWeightedMultiSig {
		if txType.IsLegacyTransaction() {
			err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{sender.Keys[0]})
		} else {
			err = tx.SignWithKeys(signer, sender.Keys)
		}
	} else if accKeyType == accountkey.AccountKeyTypeRoleBased {
		if txType.IsAccountUpdate() {
			err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{sender.Keys[accountkey.RoleAccountUpdate]})
		} else {
			err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{sender.Keys[accountkey.RoleTransaction]})
		}
	} else {
		err = tx.SignWithKeys(signer, sender.Keys)
	}
	return tx, err
}

// TestDefaultTxsWithDefaultAccountKey tests most of transactions types with most of account key types.
// The test creates a default account for each account key type, and generates default Tx for each Tx type.
// AccountKeyTypeNil is excluded because it cannot be used for account creation.
func TestDefaultTxsWithDefaultAccountKey(t *testing.T) {
	gasPrice := new(big.Int).SetUint64(25 * params.Ston)
	gasLimit := uint64(100000000)

	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// smart contact account
	contractAddr := common.Address{}

	// smart contract code
	var code string

	if isCompilerAvailable() {
		filename := string("../contracts/reward/contract/KlaytnReward.sol")
		codes, _ := compileSolidity(filename)
		code = codes[0]
	} else {
		// Falling back to use compiled code.
		code = "0x608060405234801561001057600080fd5b506101de806100206000396000f3006080604052600436106100615763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416631a39d8ef81146100805780636353586b146100a757806370a08231146100ca578063fd6b7ef8146100f8575b3360009081526001602052604081208054349081019091558154019055005b34801561008c57600080fd5b5061009561010d565b60408051918252519081900360200190f35b6100c873ffffffffffffffffffffffffffffffffffffffff60043516610113565b005b3480156100d657600080fd5b5061009573ffffffffffffffffffffffffffffffffffffffff60043516610147565b34801561010457600080fd5b506100c8610159565b60005481565b73ffffffffffffffffffffffffffffffffffffffff1660009081526001602052604081208054349081019091558154019055565b60016020526000908152604090205481565b336000908152600160205260408120805490829055908111156101af57604051339082156108fc029083906000818181858888f193505050501561019c576101af565b3360009081526001602052604090208190555b505600a165627a7a72305820627ca46bb09478a015762806cc00c431230501118c7c26c30ac58c4e09e51c4f0029"
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)

	// create a smart contract account for contract execution test
	{
		var txs types.Transactions

		amount := new(big.Int).SetUint64(0)
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:         reservoir.Nonce,
			types.TxValueKeyFrom:          reservoir.Addr,
			types.TxValueKeyTo:            (*common.Address)(nil),
			types.TxValueKeyAmount:        amount,
			types.TxValueKeyGasLimit:      uint64(50 * uint64(params.Ston)),
			types.TxValueKeyGasPrice:      gasPrice,
			types.TxValueKeyHumanReadable: false,
			types.TxValueKeyData:          common.FromHex(code),
			types.TxValueKeyCodeFormat:    params.CodeFormatEVM,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeSmartContractDeploy, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)

		txs = append(txs, tx)

		err = bcdata.GenABlockWithTransactions(accountMap, txs, prof)
		assert.Equal(t, nil, err)

		contractAddr = crypto.CreateAddress(reservoir.Addr, reservoir.Nonce)

		reservoir.Nonce += 1
	}
	// select account key types to be tested
	accountKeyTypes := []accountkey.AccountKeyType{
		//accountkey.AccountKeyTypeNil, // not supported type
		accountkey.AccountKeyTypeLegacy,
		accountkey.AccountKeyTypePublic,
		accountkey.AccountKeyTypeFail,
		accountkey.AccountKeyTypeWeightedMultiSig,
		accountkey.AccountKeyTypeRoleBased,
	}

	txTypes := []types.TxType{}
	for i := types.TxTypeLegacyTransaction; i < types.TxTypeLast; i++ {
		_, err := types.NewTxInternalData(i)
		if err == nil {
			txTypes = append(txTypes, i)
		}
	}

	// tests for all accountKeyTypes
	for _, accountKeyType := range accountKeyTypes {
		// a sender account
		sender, err := createDefaultAccount(accountKeyType)
		assert.Equal(t, nil, err)

		// senderLegacy provides a coupled (address, key pair) will be used by sender
		senderLegacy, err := createAnonymousAccount(getRandomPrivateKeyString(t))
		assert.Equal(t, nil, err)

		// assign senderLegacy address to sender
		sender.Addr = senderLegacy.Addr

		if testing.Verbose() {
			fmt.Println("reservoirAddr = ", reservoir.Addr.String())
			fmt.Println("senderAddr = ", sender.Addr.String())
		}

		// send KLAY to sender
		{
			var txs types.Transactions

			amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
			tx := types.NewTransaction(reservoir.GetNonce(),
				sender.Addr, amount, gasLimit, gasPrice, []byte{})

			err := tx.SignWithKeys(signer, reservoir.Keys)
			assert.Equal(t, nil, err)
			txs = append(txs, tx)

			if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
				t.Fatal(err)
			}
			reservoir.AddNonce()
		}

		if senderLegacy.AccKey.Type() != accountKeyType {
			// update sender's account key
			{
				var txs types.Transactions

				values := map[types.TxValueKeyType]interface{}{
					types.TxValueKeyNonce:      sender.Nonce,
					types.TxValueKeyFrom:       sender.Addr,
					types.TxValueKeyGasLimit:   gasLimit,
					types.TxValueKeyGasPrice:   gasPrice,
					types.TxValueKeyAccountKey: sender.AccKey,
				}
				tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
				assert.Equal(t, nil, err)

				err = tx.SignWithKeys(signer, senderLegacy.Keys)
				assert.Equal(t, nil, err)

				txs = append(txs, tx)

				if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
					t.Fatal(err)
				}
				sender.AddNonce()
			}
		} else {
			sender.Keys = senderLegacy.Keys
		}

		// tests for all txTypes
		for _, txType := range txTypes {
			// skip if tx type is legacy transaction and sender is not legacy.
			if txType == types.TxTypeLegacyTransaction &&
				!sender.AccKey.Type().IsLegacyAccountKey() {
				continue
			}

			if testing.Verbose() {
				fmt.Println("Testing... accountKeyType: ", accountKeyType, ", txType: ", txType)
			}

			// generate a default transaction
			tx, _, err := generateDefaultTx(sender, reservoir, txType, contractAddr)
			assert.Equal(t, nil, err)

			// sign a tx
			tx, err = signTxWithVariousKeyTypes(signer, tx, sender)
			assert.Equal(t, nil, err)

			if txType.IsFeeDelegatedTransaction() {
				err = tx.SignFeePayerWithKeys(signer, reservoir.Keys)
				assert.Equal(t, nil, err)
			}

			expectedError := expectedTestResultForDefaultTx(accountKeyType, txType)

			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, expectedError, err)

			if err == nil {
				assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
			}
		}
	}
	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestAccountUpdateMultiSigKeyMaxKey tests multiSig key update with maximum private keys.
// A multiSig account supports maximum 10 different private keys.
// Update an account key to a multiSig key with 11 different private keys (more than 10 -> failed)
func TestAccountUpdateMultiSigKeyMaxKey(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// anonymous account
	anon, err := createAnonymousAccount("a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594389999")
	assert.Equal(t, nil, err)

	// multisig setting
	threshold := uint(10)
	weights := []uint{1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 0, 1}
	multisigAddr := common.HexToAddress("0xbbfa38050bf3167c887c086758f448ce067ea8ea")
	prvKeys := []string{
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380000",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380001",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380002",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380003",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380004",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380005",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380006",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594300007",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594300008",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594300009",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594300010",
	}

	// multi-sig account
	multisig, err := createMultisigAccount(threshold, weights, prvKeys, multisigAddr)
	assert.Equal(t, nil, err)

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
		fmt.Println("multisigAddr = ", multisig.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcdata.bc.Config().UnitPrice)

	// Transfer (reservoir -> anon) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			anon.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// update key to a multiSig account with 11 different private keys (more than 10 -> failed)
	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: multisig.AccKey,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrMaxKeysExceed, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, kerrors.ErrMaxKeysExceed, err)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
		}

		anon.Nonce += 1
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestAccountUpdateMultiSigKeyBigThreshold tests multiSig key update with abnormal threshold.
// When a multisig key is updated, a threshold value should be less or equal to the total weight of private keys.
// If not, the account cannot creates any valid signatures.
// The test update an account key to a multisig key with a threshold (10) and the total weight (6). (failed case)
func TestAccountUpdateMultiSigKeyBigThreshold(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// anonymous account
	anon, err := createAnonymousAccount("a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594389999")
	assert.Equal(t, nil, err)

	// multisig setting
	threshold := uint(10)
	weights := []uint{1, 2, 3}
	multisigAddr := common.HexToAddress("0xbbfa38050bf3167c887c086758f448ce067ea8ea")
	prvKeys := []string{
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380000",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380001",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380002",
	}

	// multi-sig account
	multisig, err := createMultisigAccount(threshold, weights, prvKeys, multisigAddr)

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
		fmt.Println("multisigAddr = ", multisig.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcdata.bc.Config().UnitPrice)

	// Transfer (reservoir -> anon) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			anon.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// update key to a multisig key with a threshold (10) and the total weight (6). (failed case)
	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: multisig.AccKey,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrUnsatisfiableThreshold, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrUnsatisfiableThreshold, err)
		}
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestAccountUpdateMultiSigKeyDupPrvKeys tests multiSig key update with duplicated private keys.
// A multisig key consists of  all different private keys, therefore account update with duplicated private keys should be failed.
// The test supposed the case when two same private keys are used in creation processes.
func TestAccountUpdateMultiSigKeyDupPrvKeys(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// anonymous account
	anon, err := createAnonymousAccount("a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594389999")
	assert.Equal(t, nil, err)

	// the case when two same private keys are used in creation processes.
	threshold := uint(2)
	weights := []uint{1, 1, 2}
	multisigAddr := common.HexToAddress("0xbbfa38050bf3167c887c086758f448ce067ea8ea")
	prvKeys := []string{
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380000",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380001",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380001",
	}

	// multi-sig account
	multisig, err := createMultisigAccount(threshold, weights, prvKeys, multisigAddr)
	assert.Equal(t, nil, err)

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcdata.bc.Config().UnitPrice)

	// 1. Transfer (reservoir -> anon) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			anon.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// 2. Update to a multisig key which has two same private keys.
	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: multisig.AccKey,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrDuplicatedKey, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrDuplicatedKey, err)
		}
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestAccountUpdateMultiSigKeyWeightOverflow tests multiSig key update with weight overflow.
// If the sum of weights is overflowed, the test should fail.
func TestAccountUpdateMultiSigKeyWeightOverflow(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// Simply check & set the maximum value of uint
	MAX := uint(math.MaxUint32)
	if strconv.IntSize == 64 {
		MAX = math.MaxUint64
	}

	// anonymous account
	anon, err := createAnonymousAccount("a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594389999")
	assert.Equal(t, nil, err)

	// multisig setting
	threshold := uint(MAX)
	weights := []uint{MAX / 2, MAX / 2, MAX / 2}
	multisigAddr := common.HexToAddress("0xbbfa38050bf3167c887c086758f448ce067ea8ea")
	prvKeys := []string{
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380000",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380001",
		"a5c9a50938a089618167c9d67dbebc0deaffc3c76ddc6b40c2777ae594380002",
	}

	// multi-sig account
	multisig, err := createMultisigAccount(threshold, weights, prvKeys, multisigAddr)
	assert.Equal(t, nil, err)

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcdata.bc.Config().UnitPrice)

	// 1. Transfer (reservoir -> anon) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			anon.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// 2. update toc a multisig key with a threshold, uint(MAX), and the total weight, uint(MAX/2)*3. (failed case)
	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: multisig.AccKey,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrWeightedSumOverflow, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrWeightedSumOverflow, err)
		}
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestAccountUpdateRoleBasedKeyInvalidNumKey tests account update with a RoleBased key which contains invalid number of sub-keys.
// A RoleBased key can contain 1 ~ 3 sub-keys, otherwise it will fail to the account creation.
// 1. try to create an account with a RoleBased key which contains 4 sub-keys.
// 2. try to create an account with a RoleBased key which contains 0 sub-key.
func TestAccountUpdateRoleBasedKeyInvalidNumKey(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// anonymous account
	anon, err := createAnonymousAccount("98275a145bc1726eb0445433088f5f882f8a4a9499135239cfb4040e78991dab")
	assert.Equal(t, nil, err)

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
		fmt.Println("anonAddr = ", anon.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcdata.bc.Config().UnitPrice)

	// 1. Transfer (reservoir -> anon) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			anon.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// 2. update to a RoleBased key which contains 4 sub-keys.
	{
		keys := genTestKeys(4)
		roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
			accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&keys[1].PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&keys[2].PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&keys[3].PublicKey),
		})

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrLengthTooLong, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrLengthTooLong, err)
		}
	}

	// 2. update to a RoleBased key which contains 0 sub-key.
	{
		roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{})

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrZeroLength, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrZeroLength, err)
		}
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestAccountUpdateRoleBasedKeyInvalidTypeKey tests account key update with a RoleBased key contains types of sub-keys.
// As a sub-key type, a RoleBased key can have AccountKeyFail keys but not AccountKeyNil keys.
// 1. a RoleBased key contains an AccountKeyNil type sub-key as a first sub-key. (fail)
// 2. a RoleBased key contains an AccountKeyNil type sub-key as a second sub-key. (fail)
// 3. a RoleBased key contains an AccountKeyNil type sub-key as a third sub-key. (fail)
// 4. a RoleBased key contains an AccountKeyFail type sub-key as a first sub-key. (success)
// 5. a RoleBased key contains an AccountKeyFail type sub-key as a second sub-key. (success)
// 6. a RoleBased key contains an AccountKeyFail type sub-key as a third sub-key. (success)
func TestAccountUpdateRoleBasedKeyInvalidTypeKey(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// anonymous account
	anon, err := createAnonymousAccount("98275a145bc1726eb0445433088f5f882f8a4a9499135239cfb4040e78991dab")
	assert.Equal(t, nil, err)

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
		fmt.Println("anonAddr = ", anon.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcdata.bc.Config().UnitPrice)
	keys := genTestKeys(2)

	// 0. Transfer (reservoir -> anon) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			anon.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// 1. a RoleBased key contains an AccountKeyNil type sub-key as a first sub-key. (fail)
	{
		roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
			accountkey.NewAccountKeyNil(),
			accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&keys[1].PublicKey),
		})

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrAccountKeyNilUninitializable, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrAccountKeyNilUninitializable, err)
		}
	}

	// 2. a RoleBased key contains an AccountKeyNil type sub-key as a second sub-key. (fail)
	{
		roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
			accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey),
			accountkey.NewAccountKeyNil(),
			accountkey.NewAccountKeyPublicWithValue(&keys[1].PublicKey),
		})

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrAccountKeyNilUninitializable, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrAccountKeyNilUninitializable, err)
		}
	}

	// 3. a RoleBased key contains an AccountKeyNil type sub-key as a third sub-key. (fail)
	{
		roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
			accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&keys[1].PublicKey),
			accountkey.NewAccountKeyNil(),
		})

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrAccountKeyNilUninitializable, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrAccountKeyNilUninitializable, err)
		}
	}

	// 4. a RoleBased key contains an AccountKeyFail type sub-key as a first sub-key. (success)
	{
		roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
			accountkey.NewAccountKeyFail(),
			accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&keys[1].PublicKey),
		})

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		receipt, _, err := applyTransaction(t, bcdata, tx)
		assert.Equal(t, nil, err)
		assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
	}

	// 5. a RoleBased key contains an AccountKeyFail type sub-key as a second sub-key. (success)
	{
		roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
			accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey),
			accountkey.NewAccountKeyFail(),
			accountkey.NewAccountKeyPublicWithValue(&keys[1].PublicKey),
		})

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		receipt, _, err := applyTransaction(t, bcdata, tx)
		assert.Equal(t, nil, err)
		assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
	}

	// 6. a RoleBased key contains an AccountKeyFail type sub-key as a third sub-key. (success)
	{
		roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
			accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&keys[1].PublicKey),
			accountkey.NewAccountKeyFail(),
		})

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		receipt, _, err := applyTransaction(t, bcdata, tx)
		assert.Equal(t, nil, err)
		assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestAccountUpdateWithRoleBasedKey tests account update with a roleBased key.
// A roleBased key contains three types of sub-keys, and only RoleAccountUpdate key is used for update.
// Other sub-keys are not used for the account update.
// 0. create an account and update its key to a roleBased key.
// 1. try to update the account with a RoleTransaction key. (fail)
// 2. try to update the account with a RoleFeePayer key. (fail)
// 3. try to update the account with a RoleAccountUpdate key. (success)
func TestAccountUpdateRoleBasedKey(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// anonymous account
	anon, err := createAnonymousAccount("98275a145bc1726eb0445433088f5f882f8a4a9499135239cfb4040e78991dab")
	assert.Equal(t, nil, err)

	// generate a roleBased key
	keys := genTestKeys(3)
	roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
		accountkey.NewAccountKeyPublicWithValue(&keys[0].PublicKey),
		accountkey.NewAccountKeyPublicWithValue(&keys[1].PublicKey),
		accountkey.NewAccountKeyPublicWithValue(&keys[2].PublicKey),
	})

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
		fmt.Println("anonAddr = ", anon.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcdata.bc.Config().UnitPrice)

	// Transfer (reservoir -> anon) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			anon.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// update the account with a roleBased key.
	{
		var txs types.Transactions
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}

		anon.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// 1. try to update the account with a RoleTransaction key. (fail)
	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{keys[accountkey.RoleTransaction]})
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, types.ErrInvalidSigSender, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, types.ErrInvalidSigSender, err)
		}
	}

	// 2. try to update the account with a RoleFeePayer key. (fail)
	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{keys[accountkey.RoleFeePayer]})
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, types.ErrInvalidSigSender, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, types.ErrInvalidSigSender, err)
		}
	}

	// 3. try to update the account with a RoleAccountUpdate key. (success)
	{
		var txs types.Transactions
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{keys[accountkey.RoleAccountUpdate]})
		assert.Equal(t, nil, err)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}

		anon.Nonce += 1
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestAccountUpdateRoleBasedKeyNested tests account update with a nested RoleBasedKey.
// Nested RoleBasedKey is not allowed in Klaytn.
// 1. Create an account with a RoleBasedKey.
// 2. Update an accountKey with a nested RoleBasedKey
func TestAccountUpdateRoleBasedKeyNested(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// anonymous account
	anon, err := createAnonymousAccount("98275a145bc1726eb0445433088f5f882f8a4a9499135239cfb4040e78991dab")
	assert.Equal(t, nil, err)

	// roleBasedKeys and a nested roleBasedKey
	roleKey, err := createDefaultAccount(accountkey.AccountKeyTypeRoleBased)
	assert.Equal(t, nil, err)

	nestedAccKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
		roleKey.AccKey,
	})

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
		fmt.Println("roleAddr = ", roleKey.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)
	gasPrice := new(big.Int).SetUint64(bcdata.bc.Config().UnitPrice)

	// transfer (reservoir -> anon) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			anon.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// update the account with a roleBased key.
	{
		var txs types.Transactions
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey.AccKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		err = tx.SignWithKeys(signer, anon.Keys)
		assert.Equal(t, nil, err)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}

		anon.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// 2. Update an accountKey with a nested RoleBasedKey.
	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      anon.Nonce,
			types.TxValueKeyFrom:       anon.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: nestedAccKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{roleKey.Keys[accountkey.RoleAccountUpdate]})
		assert.Equal(t, nil, err)

		// For tx pool validation test
		{
			err = txpool.AddRemote(tx)
			assert.Equal(t, kerrors.ErrNestedCompositeType, err)
		}

		// For block tx validation test
		{
			receipt, _, err := applyTransaction(t, bcdata, tx)
			assert.Equal(t, (*types.Receipt)(nil), receipt)
			assert.Equal(t, kerrors.ErrNestedCompositeType, err)
		}
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestRoleBasedKeySendTx tests signing transactions with a role-based key.
// A role-based key contains three types of sub-keys: RoleTransaction, RoleAccountUpdate, RoleFeePayer.
// Only RoleTransaction can generate valid signature as a sender except account update txs.
// RoleAccountUpdate can generate valid signature for account update txs.
func TestRoleBasedKeySendTx(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	gasPrice := new(big.Int).SetUint64(25 * params.Ston)

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// main account with a role-based key
	roleBased, err := createAnonymousAccount("98275a145bc1726eb0445433088f5f882f8a4a9499135239cfb4040e78991dab")
	assert.Equal(t, nil, err)

	// smart contract account
	contractAddr := common.Address{}

	// generate a role-based key
	prvKeys := genTestKeys(3)
	roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
		accountkey.NewAccountKeyPublicWithValue(&prvKeys[0].PublicKey),
		accountkey.NewAccountKeyPublicWithValue(&prvKeys[1].PublicKey),
		accountkey.NewAccountKeyPublicWithValue(&prvKeys[2].PublicKey),
	})

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
		fmt.Println("roleBasedAddr = ", roleBased.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)

	txTypes := []types.TxType{}
	for i := types.TxTypeLegacyTransaction; i < types.TxTypeLast; i++ {
		if i == types.TxTypeLegacyTransaction {
			continue // accounts with role-based key cannot a send legacy tx.
		}
		_, err := types.NewTxInternalData(i)
		if err == nil {
			txTypes = append(txTypes, i)
		}
	}

	// deploy a contract to test smart contract execution.
	{
		var txs types.Transactions
		valueMap, _ := genMapForTxTypes(reservoir, reservoir, types.TxTypeSmartContractDeploy)
		valueMap[types.TxValueKeyTo] = (*common.Address)(nil)

		tx, err := types.NewTransactionWithMap(types.TxTypeSmartContractDeploy, valueMap)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)

		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}

		contractAddr = crypto.CreateAddress(reservoir.Addr, reservoir.Nonce)
		reservoir.Nonce += 1
	}

	// transfer (reservoir -> roleBased) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			roleBased.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// update to an roleBased account with a role-based key.
	{
		var txs types.Transactions

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      roleBased.Nonce,
			types.TxValueKeyFrom:       roleBased.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, roleBased.Keys)
		assert.Equal(t, nil, err)

		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		roleBased.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// test fee delegation txs for each role of role-based key.
	// only RoleFeePayer type can generate valid signature as a fee payer.
	for keyType, key := range prvKeys {
		for _, txType := range txTypes {
			valueMap, _ := genMapForTxTypes(roleBased, reservoir, txType)
			valueMap[types.TxValueKeyGasLimit] = uint64(1000000)

			if txType.IsFeeDelegatedTransaction() {
				valueMap[types.TxValueKeyFeePayer] = reservoir.Addr
			}

			// Currently, test VM is not working properly when the GasPrice is not 0.
			basicType := toBasicType(txType)
			if keyType == int(accountkey.RoleTransaction) {
				if basicType == types.TxTypeSmartContractDeploy || basicType == types.TxTypeSmartContractExecution {
					valueMap[types.TxValueKeyGasPrice] = new(big.Int).SetUint64(0)
				}
			}

			if basicType == types.TxTypeSmartContractExecution {
				valueMap[types.TxValueKeyTo] = contractAddr
			}

			tx, err := types.NewTransactionWithMap(txType, valueMap)
			assert.Equal(t, nil, err)

			err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{key})
			assert.Equal(t, nil, err)

			if txType.IsFeeDelegatedTransaction() {
				err = tx.SignFeePayerWithKeys(signer, reservoir.Keys)
				assert.Equal(t, nil, err)
			}

			// Only RoleTransaction can generate valid signature as a sender except account update txs.
			// RoleAccountUpdate can generate valid signature for account update txs.
			if keyType == int(accountkey.RoleAccountUpdate) && txType.IsAccountUpdate() ||
				keyType == int(accountkey.RoleTransaction) && !txType.IsAccountUpdate() {
				// Do not make a block since account update tx can change sender's keys.
				receipt, _, err := applyTransaction(t, bcdata, tx)
				assert.Equal(t, nil, err)
				assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
			} else {
				// For tx pool validation test
				{
					err = txpool.AddRemote(tx)
					assert.Equal(t, types.ErrInvalidSigSender, err)
				}

				// For block tx validation test
				{
					receipt, _, err := applyTransaction(t, bcdata, tx)
					assert.Equal(t, types.ErrInvalidSigSender, err)
					assert.Equal(t, (*types.Receipt)(nil), receipt)
				}
			}
		}
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

// TestRoleBasedKeyFeeDelegation tests fee delegation with a role-based key.
// A role-based key contains three types of sub-keys: RoleTransaction, RoleAccountUpdate, RoleFeePayer.
// Only RoleFeePayer can sign txs as a fee payer.
func TestRoleBasedKeyFeeDelegation(t *testing.T) {
	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	gasPrice := new(big.Int).SetUint64(25 * params.Ston)

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	reservoir := &TestAccountType{
		Addr:  *bcdata.addrs[0],
		Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
		Nonce: uint64(0),
	}

	// main account with a role-based key
	roleBased, err := createAnonymousAccount("98275a145bc1726eb0445433088f5f882f8a4a9499135239cfb4040e78991dab")
	assert.Equal(t, nil, err)

	// smart contract account
	contractAddr := common.Address{}

	// generate a role-based key
	prvKeys := genTestKeys(3)
	roleKey := accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
		accountkey.NewAccountKeyPublicWithValue(&prvKeys[0].PublicKey),
		accountkey.NewAccountKeyPublicWithValue(&prvKeys[1].PublicKey),
		accountkey.NewAccountKeyPublicWithValue(&prvKeys[2].PublicKey),
	})

	if testing.Verbose() {
		fmt.Println("reservoirAddr = ", reservoir.Addr.String())
		fmt.Println("roleBasedAddr = ", roleBased.Addr.String())
	}

	signer := types.NewEIP155Signer(bcdata.bc.Config().ChainID)

	feeTxTypes := []types.TxType{
		types.TxTypeFeeDelegatedValueTransfer,
		types.TxTypeFeeDelegatedValueTransferMemo,
		types.TxTypeFeeDelegatedSmartContractDeploy,
		types.TxTypeFeeDelegatedSmartContractExecution,
		types.TxTypeFeeDelegatedAccountUpdate,
		types.TxTypeFeeDelegatedCancel,

		types.TxTypeFeeDelegatedValueTransferWithRatio,
		types.TxTypeFeeDelegatedValueTransferMemoWithRatio,
		types.TxTypeFeeDelegatedSmartContractDeployWithRatio,
		types.TxTypeFeeDelegatedSmartContractExecutionWithRatio,
		types.TxTypeFeeDelegatedAccountUpdateWithRatio,
		types.TxTypeFeeDelegatedCancelWithRatio,
	}

	// deploy a contract to test smart contract execution.
	{
		var txs types.Transactions
		valueMap, _ := genMapForTxTypes(reservoir, reservoir, types.TxTypeSmartContractDeploy)
		valueMap[types.TxValueKeyTo] = (*common.Address)(nil)

		tx, err := types.NewTransactionWithMap(types.TxTypeSmartContractDeploy, valueMap)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)

		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}

		contractAddr = crypto.CreateAddress(reservoir.Addr, reservoir.Nonce)

		reservoir.Nonce += 1
	}

	// transfer (reservoir -> roleBased) using a legacy transaction.
	{
		var txs types.Transactions

		amount := new(big.Int).Mul(big.NewInt(3000), new(big.Int).SetUint64(params.KLAY))
		tx := types.NewTransaction(reservoir.Nonce,
			roleBased.Addr, amount, gasLimit, gasPrice, []byte{})

		err := tx.SignWithKeys(signer, reservoir.Keys)
		assert.Equal(t, nil, err)
		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		reservoir.Nonce += 1
	}

	// update to an roleBased account with a role-based key.
	{
		var txs types.Transactions

		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      roleBased.Nonce,
			types.TxValueKeyFrom:       roleBased.Addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: roleKey,
		}

		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)

		err = tx.SignWithKeys(signer, roleBased.Keys)
		assert.Equal(t, nil, err)

		txs = append(txs, tx)

		if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
			t.Fatal(err)
		}
		roleBased.Nonce += 1
	}

	// make TxPool to test validation in 'TxPool add' process
	txpool := blockchain.NewTxPool(blockchain.DefaultTxPoolConfig, bcdata.bc.Config(), bcdata.bc)

	// test fee delegation txs for each role of role-based key.
	// only RoleFeePayer type can generate valid signature as a fee payer.
	for keyType, key := range prvKeys {
		for _, txType := range feeTxTypes {
			valueMap, _ := genMapForTxTypes(reservoir, reservoir, txType)
			valueMap[types.TxValueKeyFeePayer] = roleBased.GetAddr()
			valueMap[types.TxValueKeyGasLimit] = uint64(1000000)

			// Currently, test VM is not working properly when the GasPrice is not 0.
			basicType := toBasicType(txType)
			if keyType == int(accountkey.RoleFeePayer) {
				if basicType == types.TxTypeSmartContractDeploy || basicType == types.TxTypeSmartContractExecution {
					valueMap[types.TxValueKeyGasPrice] = new(big.Int).SetUint64(0)
				}
			}

			if basicType == types.TxTypeSmartContractExecution {
				valueMap[types.TxValueKeyTo] = contractAddr
			}

			tx, err := types.NewTransactionWithMap(txType, valueMap)
			assert.Equal(t, nil, err)

			err = tx.SignWithKeys(signer, reservoir.Keys)
			assert.Equal(t, nil, err)

			err = tx.SignFeePayerWithKeys(signer, []*ecdsa.PrivateKey{key})
			assert.Equal(t, nil, err)

			if keyType == int(accountkey.RoleFeePayer) {
				// Do not make a block since account update tx can change sender's keys.
				receipt, _, err := applyTransaction(t, bcdata, tx)
				assert.Equal(t, nil, err)
				assert.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)
			} else {
				// For tx pool validation test
				{
					err = txpool.AddRemote(tx)
					assert.Equal(t, blockchain.ErrInvalidFeePayer, err)
				}

				// For block tx validation test
				{
					receipt, _, err := applyTransaction(t, bcdata, tx)
					assert.Equal(t, types.ErrInvalidSigFeePayer, err)
					assert.Equal(t, (*types.Receipt)(nil), receipt)
				}
			}
		}
	}

	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

func TestColin(t *testing.T) {
	gasPrice := new(big.Int).SetUint64(25 * params.Ston)
	//gasPrice := big.NewInt(0)
	gasLimit := uint64(1000000)

	if testing.Verbose() {
		enableLog()
	}
	prof := profile.NewProfiler()

	// Initialize blockchain
	start := time.Now()
	bcdata, err := NewBCData(6, 4)
	if err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_blockchain", time.Now().Sub(start))
	defer bcdata.Shutdown()

	// Initialize address-balance map for verification
	start = time.Now()
	accountMap := NewAccountMap()
	if err := accountMap.Initialize(bcdata); err != nil {
		t.Fatal(err)
	}
	prof.Profile("main_init_accountMap", time.Now().Sub(start))

	// reservoir account
	//reservoir := &TestAccountType{
	//	Addr:  *bcdata.addrs[0],
	//	Keys:  []*ecdsa.PrivateKey{bcdata.privKeys[0]},
	//	Nonce: uint64(0),
	//}

	signer := types.NewEIP155Signer(big.NewInt(8217))
	{
		privkey, err := crypto.ToECDSA(common.FromHex("0x3cb041196adccd10e3371a2c78187e5f6e2e7f3b621ce63c722b00c3f2447171"))
		if err != nil {
			fmt.Printf("crypto to ecdsa fail: %s", err)
		}
		addr := crypto.PubkeyToAddress(privkey.PublicKey)
		acckey := accountkey.NewAccountKeySerializer()
		rlp.DecodeBytes(common.FromHex("0x05f8f0b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5db84e04f84b01f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5db84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5d"), acckey)
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      uint64(0),
			types.TxValueKeyFrom:       addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: acckey.GetKey(),
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		assert.Equal(t, nil, err)
		fmt.Printf("tx addr %p\n", tx)

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{bcdata.privKeys[1]})
		assert.Equal(t, nil, err)

		fmt.Println(tx)
	}
	return

	var txs types.Transactions

	// make TxPool to test validation in 'TxPool add' process
	poolConfig := blockchain.DefaultTxPoolConfig
	poolConfig.ExecSlotsAll = 1
	poolConfig.ExecSlotsAccount = 1
	poolConfig.NonExecSlotsAll = 1
	poolConfig.NonExecSlotsAccount = 1
	txpool := blockchain.NewTxPool(poolConfig, bcdata.bc.Config(), bcdata.bc)

	{
		addr := *bcdata.addrs[1]
		feepayer := *bcdata.addrs[2]
		acckey := accountkey.NewAccountKeySerializer()
		rlp.DecodeBytes(common.FromHex("0x05f8f0b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5db84e04f84b01f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5db84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5d"), acckey)
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      uint64(1),
			types.TxValueKeyFrom:       addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: acckey.GetKey(),
			types.TxValueKeyFeePayer: feepayer,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeFeeDelegatedAccountUpdate, values)
		assert.Equal(t, nil, err)
		fmt.Printf("tx addr %p\n", tx)

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{bcdata.privKeys[1]})
		assert.Equal(t, nil, err)

		err = tx.SignFeePayerWithKeys(signer, []*ecdsa.PrivateKey{bcdata.privKeys[2]})
		assert.Equal(t, nil, err)

		txs = append(txs, tx)
		txpool.AddRemote(tx)
	}
	{
		addr := *bcdata.addrs[1]
		feepayer := *bcdata.addrs[2]
		acckey := accountkey.NewAccountKeySerializer()
		rlp.DecodeBytes(common.FromHex("0x05f8f0b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5db84e04f84b01f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5db84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5d"), acckey)
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      uint64(2),
			types.TxValueKeyFrom:       addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: acckey.GetKey(),
			types.TxValueKeyFeePayer: feepayer,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeFeeDelegatedAccountUpdate, values)
		assert.Equal(t, nil, err)
		fmt.Printf("tx addr %p\n", tx)

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{bcdata.privKeys[1]})
		assert.Equal(t, nil, err)

		err = tx.SignFeePayerWithKeys(signer, []*ecdsa.PrivateKey{bcdata.privKeys[2]})
		assert.Equal(t, nil, err)

		txs = append(txs, tx)
		txpool.AddRemote(tx)
	}
	//update the account's key
	{
		addr := *bcdata.addrs[1]
		acckey := accountkey.NewAccountKeySerializer()
		feepayer := *bcdata.addrs[2]
		rlp.DecodeBytes(common.FromHex("0x05f8f0b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704b84e04f84b01f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704"), acckey)
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      accountMap.GetNonce(addr),
			types.TxValueKeyFrom:       addr,
			types.TxValueKeyGasLimit:   gasLimit,
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: acckey.GetKey(),
			types.TxValueKeyFeePayer: feepayer,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeFeeDelegatedAccountUpdate, values)
		assert.Equal(t, nil, err)
		fmt.Printf("tx addr %p\n", tx)

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{bcdata.privKeys[2]})
		assert.Equal(t, nil, err)

		err = tx.SignFeePayerWithKeys(signer, []*ecdsa.PrivateKey{bcdata.privKeys[2]})
		assert.Equal(t, nil, err)

		//blockchain.SetPubKey([]*ecdsa.PublicKey{&bcdata.privKeys[1].PublicKey})

		//txs = append(txs, tx)
		txpool.AddRemote(tx)
	}
	// Generate the first block!
	fmt.Println(txpool.Content())
	time.Sleep(1000)
	//pending, err := txpool.Pending()
	//if err != nil {
	//	fmt.Println("pending err", err)
	//}
	//txsMap := types.NewTransactionsByPriceAndNonce(signer, pending).Txs()
	//for _, tx := range txsMap {
	//	txs = append(txs, tx...)
	//}
	fmt.Println("transactions", txs)
	if err := bcdata.GenABlockWithTransactions(accountMap, txs, prof); err != nil {
		t.Fatal(err)
	}

	// select account key types to be tested
	if testing.Verbose() {
		prof.PrintProfileInfo()
	}
}

func TestLoadRLPTx(t *testing.T) {
	txRlp := "0x21f901bc808505d21dba00830f4240946f2cdd2f9e734deb4d8d0dcdc2fac937ee2e42f9b8f305f8f0b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704b84e04f84b01f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704f847f845824056a0eff50a32b273f69eeff14ba02212983dc68641f11e498e7eba982c3cd32ec4c7a0142b545341fe304c95253fcebd718608869874b9ea5b8503455f037d917ab876946d8202b8da35d424075984d4bb2fd2d455fc2047f847f845824056a0f6c5d071b909469fc9ffb60e1ad4c1e4dcf880e301270beb7eaf8beb792c7c3ca042158b01234af927ecfd05e179e79a16a3b4ddaff5b63ccba011e292a0db1746"
	//txRlp := "0x21f901bc068505d21dba00830f424094e7d3e5a9a6fd4962da86713070b79012929f783ab8f305f8f0b84e04f84b02f848e301a103e7904ddf9dc32fd972bfbd0c425d9d9401413b9a431eab7ef772ddad4ea3adc1e301a102997f5aa55ace3ae15c9b0b13f4dac88a8dad9dacab89466021c2a53331fd3d55b84e04f84b01f848e301a103e7904ddf9dc32fd972bfbd0c425d9d9401413b9a431eab7ef772ddad4ea3adc1e301a102997f5aa55ace3ae15c9b0b13f4dac88a8dad9dacab89466021c2a53331fd3d55b84e04f84b02f848e301a103e7904ddf9dc32fd972bfbd0c425d9d9401413b9a431eab7ef772ddad4ea3adc1e301a102997f5aa55ace3ae15c9b0b13f4dac88a8dad9dacab89466021c2a53331fd3d55f847f845824055a0ead251db837dc6dc7aadbda34fcb8afd5243bad41ce214e6000a61daa45e9520a06dba0d136a919afa9841ae61b6597ddccd8ffce7c7a0dd2eb6e4448bef9f0a70946d8202b8da35d424075984d4bb2fd2d455fc2047f847f845824056a0fa4425aafb9086459ea18b052bbc7839ed8968172e58c719ca3eb42920911da6a0394957ce10c3b6f98fa00728ae6e39d351adfddf02d1697e8f93d766e303bb71"

	tx := types.Transaction{}
	rlp.DecodeBytes(common.FromHex(txRlp), &tx)

	signer := types.NewEIP155Signer(big.NewInt(8217))
	pubkey, _ := types.SenderPubkey(signer, &tx)
	fmt.Println(crypto.PubkeyToAddress(*pubkey[0]).String())

	fmt.Println(tx.String())
}

func TestLoadRLPBlock(t *testing.T) {
	blockRlp := "0xf96d09f90270a05856d7e7bc166c81b3fafbd133c68e85b2548e659f5d09acf60d02685e7c9d9494186de0382923086f73367bab16af09aeda4e54bfa0f65afd0e70e43d356d8d2d457967690bff4fb9ca29631f43e94b4bd8e632f2d2a0c14c72ffa2055184abaacb1d0fd080301555c0af870fce07dc08d5b6ad0f7622a0fdfa39a06d8e22c9413163db19cb7c6392e63b7a6671c68e31a5ca40d6b94aeab9010000188061046034040800000060000206004510162e040020008011a00880020010091100002080c20950048000204020086040100b00020408001080002040086408008280004800208089080004282001500100a000200141020200920a0288001002030200020009a10040c2000a0010901820010200280000807041a002e480000058888870000224c000402040011402120160080001010806008344030006020d8022e0000182040140400000464200480080800040030886000010500030000c06040081094004000060600a464040e1000100000081004100b840a8040050a0c80000928098000040060800200080100040000040808040008400801201840479179483772fe184618fb2b422b8c0d883010503846b6c617988676f312e31352e37856c696e757800000000000000f89ed59452d41ca72af615a1ac3301b0a93efa222ecc7541b84148ef82a732503c4811a459a22d5f53c9a25fbef80a97880d14b7fa757501e4690010b2104925dc710779eda197d267aa6a1315556bd65fcbdfddc5bff74347df00f843b84176182a5ce5b8f0a849a4727932d404dd8943ea57b975316820633f930ee6cb824f0366393fd5daa48323934972bdf7366afda4391f6167ffd29d70c5af068e0c008080f96a9331f902678201c08505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380940d60f9a6975a409fcb2fa625160c9986cc8f49e4b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd0000000000000000000000006c01a94eb731c35ef29a804b16cc44c0c58a6816000000000000000000000000000000000000000000000000057592d843086000909b7beb98d862ae3cdea2f571fb287cd978f0612b59b02a21e4e471f00424b00000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000004118129c37826dac4476c058f8979be2be51ca5a25067a25bbf364a72eb6282d3929317988cb7eb87f126f9879e19ecaf0abde45ebd12deb13f09a5f247e54da6e1c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a06f149b0cd805a017f215d5836e52de4a11be5f8f6484b40c962c2ca097d3dfc4a050b66087896d33104929510db1bc24dc2cc8b304a437716e669294cc0b6c603094c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a09f2f3d8113effac5ce93ea88f037c04a15c9d5ce6f8dabc91644166c45868a45a00a37fb56854d282f942ff62c4d52441f077db899528891098e08985bf37f62be31f902678201bd8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f38094fdf1608f36740bcc4563ab57ee41d1d6bd348c41b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000b67b9434ec646938421b0c3033a577b1d8babafc00000000000000000000000000000000000000000000000002ad53fbcdb6b80016caf9af7b07d5ba21447f4ea6ac717a04200fd47b577d4901cea7fa7cab501d0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041343f2bb5e9d0ae269b587495106f0639302de23bef62be1ff3c108ea3f8aeb206f1353704c766e7dcaf84a27380a457635f1d7b916851f763fa4c3e43de0da1a1c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824056a013acea5d806d043c4792dac9cb756f7c16e43ff1186d21faa2e2eba9ca23bceda079b9af3b88c2a02883db653cb27e95687c64c0271865f7cbae8f892e30ac471d94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0ace2db15f578caa74cb329ad3c39ba76f7a9439aebeb29b8d14db77d21e8cd03a0055f4f496e7be4e4ae36a3926f8b24ae65d53198893e54d8f4ba251af3d4d15ff901ef8208d88505d21dba00833d0900944d946ce280f8888507b69043bc6c84a66d7c05f780b9018443076c9a000000000000000000000000000000000000000000000278738640af254aaaaa0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6a2ad8cc6e4a7e08fc37cc5954be07d499e765400000000000000000000000002cbe46fb8a1f579254a9b485788f2d86cad51aa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001824056a037866a158589aeaec304895bc9154da5578aaaac55d80e295353463c1ca2c8afa040e94cc1859a33005f8f6e8aa388e3b076d0dc816b95fba3a84bd43a1e8454f631f902678201c18505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380946445667072a877ed14b0da617342d9cd2aaffbdfb90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000fce09376730a9523f41453895518713f6f89c14800000000000000000000000000000000000000000000000005731beda4f3b800974c21a088efc97deb598319e20b726db9e6939a08364bc8f589adc64c9687100000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041f236dd8e081f91e6044c12556baa2a8033b916b8b999fa201f6e2eacca8c5768052bc884fe89d3bd8054b7304e73c0dace609d305200ed17a792b94e82590be81c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a03bd2615f4cd6a41599512cb678200d8ae41252ee84dc48524782d7618978e0dfa061b3ab11d70e698999ddc24dd5284c7e89d1378c3261e096a837a7ad5ec3e95f94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0afa19f4560847a35c58417d16e2e3f70014263df531fa4e397483a2f659b780ba022bca3056833bc6411caca3a384b55a7c6879d81839ed0ee163ea79b9b1ce10331f90124128505d21dba008405f5e100945096db80b21ef45230c9e423c373f1fc9c0198dd80943b1c2a2e623ec75f62bdf87a4ed040b923150f36b844a9059cbb000000000000000000000000cfc769b7c8e03485a078d983011621703d6ca3540000000000000000000000000000000000000000000000000830cadc995a9000f847f845824055a0db0b2dadd0494f70063ebedd0853bbc0f53355494c5a96b0004be12185951716a0724189b327cd693d2c48c5659dd22c81fbdbf44bb6246b115a69b3ce3614fdf094c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a061c3d68ba854c783cc7e8213b8ed9bf0b2a146244e1ff7e0de30f6353884c2bea05a6e2bc07da68ffee90349f14faaeae34e54ba8620af4e1744bd0c70b2f83bbc31f90124018505d21dba008405f5e100945096db80b21ef45230c9e423c373f1fc9c0198dd8094aa9a0394cb770dda905f264eb8a2e79a7594b149b844a9059cbb0000000000000000000000008dafcb96723e4021446710d36f3eb9d34e9e9c2300000000000000000000000000000000000000000000000010dcf87973c1c000f847f845824055a030196c794a22ca0c8fde4400550f02a6560df2be666f88af970bf73e4e8d5c96a014c55bc821a02e79f5c59c3d98de80dbfd9a0a1121339700cf5147b03720eaad94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0c36e23494f82057461815b58f4f37820c74198519a2dc3665f67ba44050ae8baa07b7c109de660a1949d3acd0481a99fac03d40955285d27429ad1535054b3ad60f901d08203098505d21dba008401c9c38094f8d504c6a68c4fe07fddfa62ea8864dbf8d851a580b9016439b84446000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6a2ad8cc6e4a7e08fc37cc5954be07d499e765400000000000000000000000002cbe46fb8a1f579254a9b485788f2d86cad51aa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000824055a0639a25c1b99fa31fd77273f1178d2755bceba3c4a967cd058a8a805ef9b80572a066caf6681180236278dde0144020102941a3b8537260807343455d24925a826131f902678201bf8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f3809405552671c4ee1e3e4d1bf08762561ad0aa3ce24cb90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000ae34d82a688de1a0627f67aceafc4a37e0dfd89a00000000000000000000000000000000000000000000000015ee06420c719000c5b4bb95931384e0867b4966b97ad4346f410370cfd1d37a14231b2a0bd9effa0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041145ae9061bf6e344f01e094231e14e445dc131d40fc28ee6243b069930f5c4681957a7254a5b46fc8e1c6067eb08b01afcdd17f146a1f35ab77a36bd7453803a1c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a0bbc04f32874233235e714b7e1aadcc92ae5a1c5672db44f3c69a6120a1708db2a05ad8c517c56057c247d518b1d47b15341215773b8a8392bf11af7d8515f66a2d94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0a2394cc34bf4bdf8b492ca05b18a7f25c8781b18914beb0bfbc5669464a24822a0712ab9e8367f4b89f793124386fe92f9194406ceb06c45229fddcbcd8921752231f90264188505d21dba00830f424094507e470fd39649c12e2aecdd02f7dd871dc383708094bae562799c91b5cd7f23e306241ae41539292339b901844ff4bebc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000bae562799c91b5cd7f23e306241ae41539292339000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000576616c7565000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000576616c7565000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000576616c7565000000000000000000000000000000000000000000000000000000f847f845824055a09a6572e1d8df656d3826585a676b70d8ec0cea439718d8089b1321a7073471d1a0221e5ba99bd1ee6f4d2352aff6e1fbfcb38707fb00fe584c78cb954b4a58bd7c9410f0eaa52a474f0605afbb8c17bb9189e6ed006cf847f845824056a00fcaa63dfafa0fa74e6cecba23a70d1252aeb5130172b891c90b474bcab4186aa07ef4cc3d4f8570521935261a4b3f1059939d28dd97ff587ee575b9ea0a934e1531f901a4118505d21dba008405f5e10094c6a2ad8cc6e4a7e08fc37cc5954be07d499e7654809479aa3bbb0476a7d40549e21e2ce0a0ea1a297d86b8c452f28c170000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd0000000000000000000000000000000000000000000000001b6fb70680f2800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008686e1fa7faef26600000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000f847f845824055a08672da40ca21704fdaf496659e50f254dc281ee7318ffe88222b705cd09fba40a0185fd3a3db1019172c307b68eb44245c449dabe9e504a3c68ff03e327fe0a24d94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a08c6388b3d53c6119dc4d40519104e0e38ecc992a7947c1018ad892f795a6a965a00687366ab936d4c29ce86e944c7cafd115c9f2030e3b67bd51759038f85189c3f86e808505d21dba008252089486d2660297c82ac656715e00c979fb5ca65eecc58844b3b8d2956e8c0080824056a0d0e899894d211b8febbe531ca2caa6e644e574a0dd3af1f73b505f6a2d60deb7a00c7e4daa476caaad2e2312a83f8c0ee264cccf99cc2c51ae5a1100ec9eea0bb931f902678201bb8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380940a6bd3e0f15c7fac897a1d281d348e90cca69e82b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000d43bee10fa2d14df4ad6096c5b1a2d700b1e18d700000000000000000000000000000000000000000000000002f4cc8fb60dc00057e980cd7cdd99fea72401cdb7634f3ab2fb8649d3a9fabeee69a8eac373c3af0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000413e7a441b2492cad781aa549af0b4e5027cc10a2fca70d14c13e8ddfc637afc9c56b7f9a7548501fd5e4f9cab52048657f2141c2364b81a8471f86368f6689dbc1c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824056a093ea61b5fcc825d1464b483167daf7c52c159fb3bc62f0063d0e063a6f40db7ca07139daf468653e639d622018c2268316ce2fe23aea3e315fcba461c8c297d0db94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0aee733c67405e0525b5fbc73016c92e24c75e5ae96b39dd51cce50b082583ed2a06c8a548a3a3d66def84d740a020c0774e4c44bfe94f9ab3a4eb9d40fc980e3cff8ae8201d18505d21dba0083204c8e940cddc42b218a109ca4cf93cbef1f8740d72af7b280b844e2bbb15800000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000000824056a0814f00e4cd5bc70052c0f71b406c00d1629a6b2f253354d18ca6c04b8a3564c0a046def501e26dc349936401578bec4cf151437b7b00a747ace00d8f3bb46a4775f86e188505d21dba008252089486d2660297c82ac656715e00c979fb5ca65eecc5884560bdcbf0f74c0080824055a0d4442ecf2b92defbfe57da0045cbd8bb13b7a0d064e3ae105a99d717a00db37fa06f4ea77c550a566572951326a7000c589255f2cec67c52b42a9ee5a9436c15fc31f90124098505d21dba008405f5e100945096db80b21ef45230c9e423c373f1fc9c0198dd8094d56c8d34d851a2a099af15cd78dc93c3dae92abcb844a9059cbb00000000000000000000000008988ac8f8f9fb0b7afcee9298a24f0f79352aa60000000000000000000000000000000000000000000000006ee38f8d158b4000f847f845824055a0a93a1a3c66fef5dde5f0b221a9e1cb3320acd5a21a6103ce7d888daa0dd5d6d7a00fd57df1b9654b915d0336ae5b3020fdbbd5fd599de071bd68a5d60aa80793a794c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a0fbeecb3f331ac498bce5fb26d14f50279030feaee529a73fbbb62451d2eb5006a07c2bc82dea00d9b13d1f69d97cb1cdfb1d99abdda76bb9e844707c5826bdcb77f901ef8208d98505d21dba00833d0900944d946ce280f8888507b69043bc6c84a66d7c05f780b9018443076c9a000000000000000000000000000000000000000000000278738640af254aaaaa0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6a2ad8cc6e4a7e08fc37cc5954be07d499e765400000000000000000000000002cbe46fb8a1f579254a9b485788f2d86cad51aa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001824055a02688946889cb6b38e8230c95fc8ae4a5310d6576cc5d0ac426ef0bbf728391cca0790570b7ffbad49a840846836acfacb28d7822ecf81acf48e9125fb99071208c30f8a68208dd8505d21dba008302146a94fc4a062c77566ddb169ce8e7da396eb424cd42d180947ef5bb5ef651018bcfd233c71799466f033b6aa3a449df728c0000000000000000000000007ef5bb5ef651018bcfd233c71799466f033b6aa3f847f845824056a05d97bb05907c4e5634c2675cc1eb9c2a818c540e843abaf77789d597d4903b94a00a8692e92143d544abe6c01a8a7ef3b1182756890d8a019e4dafdfa2799d9f9930f8a68208de8505d21dba008308719e946783d1049fe76b9db8784fa266c45a5ccccbfc5380947ef5bb5ef651018bcfd233c71799466f033b6aa3a40e5c011e000000000000000000000000e20614dc76e7fb5b02c6a60e1dc27459e2474336f847f845824056a0983c205963e4e6d4b7000c14d6c4c3697442e7d1b41e74d32000de28f59b2024a0021d985b0481269e88a4745c82d16e769a694e4b2c227ddf4e4150ee36d52ffd31f90184808505d21dba008402faf08094e3656452c8238334efdfc811d6f98e5962fe44618094108b18ff954aeeb48b094186cfb88c69a8f0a116b8a47c471e910000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000005fe53fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff44ea9000000000000000000000000000000000000000000000000000000000000001654686973206973206d792066697273742073706f742100000000000000000000f847f845824055a0f7073cf01507088b13900a2dfc13bd20382a5b47733d4f2674368c4936a8b2f5a05f75b0b2755d8939bd1077b3f150f205975984a333099a00cc747dc6a13deac394ae1ccb1a49caf961dbede6db744f6f27f7bb2b41f847f845824055a058b63f68c8231d4b4ee79b833ba52183ee5360ee55f3d938f0fed7430d69584fa00dcd914198a71a25034311bda97a8bcc6386350431396c1bc13c722e741bf95a31f90124038505d21dba008405f5e100945096db80b21ef45230c9e423c373f1fc9c0198dd80945fabfb2e814e8ba051de06f61fd96adc543ee710b844a9059cbb000000000000000000000000f4fd174c325da0a70e975eaf45d18d8e16f347ed00000000000000000000000000000000000000000000000005ade7caf2976000f847f845824056a05bd5ca0f67ce132a811431dde26b44b0faca0e6c350d7bd1f78371080461f34ea07ca2b49bcaa335ab8d3774a71a4856cb02d02e9c7dcd85096b100c8cc4e73e8e94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0ed6065c8c679e3d818b22b65a80e925c4cf9447e132eedfa9e9823668d1632d9a058300045a1cab81e0b2333de18e63173c929c09b7a1aca22700dff412e74de9f31f902668201bf8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f38094a00d1f68b2d49b6e2ace3d1981359c1ac94d8f66b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000c7bcab8bb7a0179320f4b2fb5d3e98f2ad5a6fce00000000000000000000000000000000000000000000000041513d38dc28c00081dd003eb9f86c47d71209bb3e8abeb08b4f8c53e6190b0492d521e1280300440000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041e99d38b54ebaee5080dda90edf9065701e8f3f3d9cb81413819ef16eeb770c5843c6fe3829ea9b68653434babad0fe086b84485e0098a78e1d4b880f0c8fbc041c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824056a0ecb0bac59e5e5c4b14b07b7670597018f0e666d37427db965d1233a9f68200b2a07ba54b07a996a36749494e7506d5d552a3a770d6f17fc434ac81961fb917b5e994c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f846f844824055a0efb549d37d8de2d1e4de6431f2ce03e7045e2155cb49c7087ba0b6097c7e25059f145b336d6df0f98017a7dc7510bf57223dd4729babac126aad669bfbb9773331f902678201b48505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380949d116869dc93e7dc9427f5af6035960d5de52e73b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd00000000000000000000000043c719db7faeebdbd627662a9881cc12414511ce00000000000000000000000000000000000000000000000002aa28ce2709e000a149d6d1227d242640f9b25a5fbd0606d8bcf17e9efa1e1a7f8da21135b197540000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041f7eff2cd2fde409507022b75ffe97a3e3cf72f98f742e4c4650bffa7af6ce9c536d55cd10b5cc9d9c98e21c37c9efb1a5aedabdddd3eab100c5f4a7660992e641c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a018a29c7d4948bd078a5d790d9e839e7c3ff1d3b69b8f5b28ac36e9f0a5690b7ca04db39f1f26e4102db3d258e857174ac495aea615ae959bab61200da3ff26c9cb94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a099320a50eceebb48c08713108de7d4d72b3991d1bbb449ab74dfc96762d5af15a05aa5820cddd69fed8540f38df48bb94cb915098c32ce9facf574c81bf5d915d731f902678201bb8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380947f44a7ea1a4c0ee44206501aa1e7fd84c80e3803b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd00000000000000000000000014d1bf5ec9d443e3674138521dd78089d220dbf0000000000000000000000000000000000000000000000000237dcfda51e39800028460586a9df98fe5954a9a457eccc5f0ed33e27ac1a6b81a9ba091d3ef46fd0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000415a668c6a12d3c66d43681bf6ef202c4620b76c51cf515cb63723cf6d3148218e358e4093475252cc44ea3ee0d5e0e4d3466d508009cebadd26c67f84ea6aa0b01b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824056a0a5c423d67ca6f5c3de112bc5ca0a7af7c2204962b21f52eb5e517b0a88bc1f5ea0046f6db9125bc24d75883d01f8e06deb227b0e286f2af792a809a2c39b6c116b94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0f91b4bee7cf975c330d61fccb54018b7631613c1f1973534282268a3e8fef67ea004f293582a5e44a7f1244e6c14e1d92184256ee2548cd2a50cde99ee2f1e979131f902678201b98505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f38094826f8ad5da80cd9030383d695542646479605139b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000f2599a5b31b216b41f90c8407fecec9ea571dad70000000000000000000000000000000000000000000000000830cadc995a9000c9c7a7ae3f5689a53123293402f26a85249eed087d8e9a37c150ce440268b9660000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041a6da7ece5173fb205b13ef125b860fd59f538105116aee5659c157238d1c743b5c9a1f966b4aa002294e45982bcd173fa0d4415fafbf5b4286b9d6ef90e9aa761c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a0529ecc46b20940394591d10a3e53f39c849062f46156a6be61b9a4e78fb7b62ba03a23fb15e3a10fef42359876fa90dcdb373c8d9e7b57d953f7dc31a05ae37b2a94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0c9c39ccf2f392945e03fb00bf5ddebaf8535adc169c9782a2ce16e6421ef92b0a05e69e0751ff476c4d587b672777e72dfed1994da66309e1d83382d5d9d19083309f8e6138505d21dba00830210009424899e8b8bdb77d7c2b7d366aa680cc51ff20671891b1ae4d6e2ef50000094a5fa6538ca50b37cdedb69b600f108c30450a01af847f845824056a03a372f23c789a619fde322b5bc01bd57c5fc4b5199cd3d3a5560a57a6cf9f793a0237c2fe5550981d862810225b61da860bcb81af9a973a5c5f1316d0f2716767e949e34736599bd59b81cb94b67295ff937094d2147f847f845824055a0db65fa9d82e96c2336baa1e0a94af4d5fa0b52c4b884e31b65e744ab4eb91a92a07aba08502a0ee3e517224f69c4fa1f5509c237eaaa92755dde92835c812b154021f901bc808505d21dba00830f4240946f2cdd2f9e734deb4d8d0dcdc2fac937ee2e42f9b8f305f8f0b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704b84e04f84b01f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704f847f845824056a0eff50a32b273f69eeff14ba02212983dc68641f11e498e7eba982c3cd32ec4c7a0142b545341fe304c95253fcebd718608869874b9ea5b8503455f037d917ab876946d8202b8da35d424075984d4bb2fd2d455fc2047f847f845824056a0f6c5d071b909469fc9ffb60e1ad4c1e4dcf880e301270beb7eaf8beb792c7c3ca042158b01234af927ecfd05e179e79a16a3b4ddaff5b63ccba011e292a0db174621f901bc018505d21dba00830f4240946f2cdd2f9e734deb4d8d0dcdc2fac937ee2e42f9b8f305f8f0b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5db84e04f84b01f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5db84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1027836b869758219a9995bc2a670f7fba2d004fa777a4ef709c5bc62ca36111d5df847f845824055a04cfb8ef0210f971180463972ff5a219db867990360b69fece893243f3b875d04a03c5fb576d6154632052930ac6f66d26788fdf76df2fcc69b36ba121437e80547946d8202b8da35d424075984d4bb2fd2d455fc2047f847f845824055a062a31360072e104bc75376cddd2de5f207b571b4d1203b1817b2023503b69b26a042ba42e5e7e91552b1a06f820c17a20bff35f34f6f323242819185aa981e709821f901bc028505d21dba00830f4240946f2cdd2f9e734deb4d8d0dcdc2fac937ee2e42f9b8f305f8f0b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704b84e04f84b01f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704b84e04f84b02f848e301a1027f7de95a473a7695f2a8cdba970be125de821e117316a0d5f8190432ba53b21ce301a1035eaf7ed2b7329e1301b300e63de3f8424ce6fffd206c6df8a5022e59c9bad704f847f845824056a052ee28ffd4bce6bf8ea170028a011be3a1f98a6867654e2361cda493555bbe1ca065fe2c613a6fcd37b665a44975f8b9124f8c947da90536b7b173950b7a8920ac946d8202b8da35d424075984d4bb2fd2d455fc2047f847f845824056a06f796ac4b6fb70a9ff5b1f80a6ce6c63dca6afed2de3868edf4c754fb8850503a031a46dc35f913ddb9ab2c52af785cb6166e922652748431862253f72ff36487231f90184808505d21dba008402faf08094e3656452c8238334efdfc811d6f98e5962fe446180948b71177b01acd0f3cd2adf3d69c66443d5792ae5b8a47c471e91000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000580cfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeee2e4000000000000000000000000000000000000000000000000000000000000001654686973206973206d792066697273742073706f742100000000000000000000f847f845824055a041a7c01fea13afd369d350870dc96a12dc556bf032f3768b16c9276649ba38e4a017680dc63d5ef7e06fcbd7b6fae34f6715a60029cf5dfac0a2e7d8a26f375a0694ae1ccb1a49caf961dbede6db744f6f27f7bb2b41f847f845824055a023e0ce84597a2db58023cde77e8565a470504e1b33649c2e815459816d160226a0092f45f86accc5d068668b0ad3737dd63e51905c8441b314b64a79ab31f9e52b31f901a4428505d21dba008405f5e10094c6a2ad8cc6e4a7e08fc37cc5954be07d499e76548094e8f01e1c799667eb65405a10f7ea365d4a2ae714b8c452f28c170000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd00000000000000000000000000000000000000000000000010865ca1747e50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000510670b4490a3fd500000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000f847f845824055a08ff5578c9f8201ecb2e9b6a0c9265780550f8b2793763f7fcb5e28d0e56b14f3a02d5ae17b07fe59e081efd23736dd613a07139db22a86cd4cfdd36926fb296dd294c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a03792630fa934686ea24520678e39140d9071152bdbe6e2d445528df670b910d3a0032f3fa4286be7574e4367405c1ecbeccc1dd88ec8bee3455c62b99c3e8f18c731f902678201b78505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f38094338278d90656ae75a821e60eb12064763db568adb90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000d3d762047271611d6364716643039e9f8ba5b2930000000000000000000000000000000000000000000000000298bf7673757800e1bf1228aecc93028dc2aa5beb1d2aae3558bb5d4d3febe304b99889565dedf90000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041f1beed38a69855e9b79cb61e8f59e37c69ba03ed44b74cc7037586b591e41e4e1f2f80bff7303741fe7d5624fd7e5baee60ea2488d31dd1fea5630b47d9fba371c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824056a08a00ba665d11514264a2e064ea59cb7a89f76edd443aea0e68e80448e9fd2a0ba05e5fda054d950a1b313371d61d99764a6996e23dfbc480ec10e415f30c5f858394c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a009452c5eae1b4e4b5b4531abcc31a03eaca2439a42f784c71f2da6940f297027a03f9833763867b5e4a89e073c83c3e71fc3179ca8bf391de9fc690901a85c6aa631f902678201bb8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f38094db4ce3657564d51581df75dc6eb32a23aed4998fb90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd0000000000000000000000006e03333f1435f6fc74bdb1e66b6c0821e07a4d6900000000000000000000000000000000000000000000000003294211b657b8004d7334cca21b81bab04150a28fae1e0a802a379638143449351108af179446370000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000412fd3dd5c025d21aed5ad5240aec500e2b5aed9344bab6a82c6bc7e63ae0c8f242601e40da5f207550c597d93f3c22e0fe2f19cb8f6a7af4040f746a87f49d1451c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a00f9434562b36a55dff6b17da3ccd14fad14f949aa3836acefe998c7bbbd4b19ba00a8b992836242f48e5097a15b88734e6f84ae60e6be718b1594bf7341002cd2e94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a0593d14a7db975ef748fc745f4e2bead665be33764d633d72777f09d4ec1efca6a011e22b9d9c805ccd40c4d19b1a8fa743262f78431be368cc07dee7a1dc8c430030f8c88302981f8505d21dba00830f4240943513b2bc58f1f260107fd1ee0dabb5b0637b9ed580949ceda95ab840a5b546b9d828e27d4a94d6eb3ecfb844a9059cbb000000000000000000000000af3a6624c4f7333c85e42bc5d4116dafc9418faa00000000000000000000000000000000000000000000000000000000447c5940f847f845824056a02872f3448addef3ececa7641f41aca19b745aea760a6201dc49b8c5e17902209a018dc50a59e47cfcbf056b48f98b01a5a461f38ae1e7fb82cd239bc2f105d713d30f8c8830298208505d21dba00830f4240943513b2bc58f1f260107fd1ee0dabb5b0637b9ed580949ceda95ab840a5b546b9d828e27d4a94d6eb3ecfb844a9059cbb000000000000000000000000b6cd3c5cb4541b26672d4948b338531b98065cb7000000000000000000000000000000000000000000000000000000003ba26b20f847f845824056a09c8820cb4065ebe943195dd9047bab7737223391102163788b1e54b8aa38310ea013578801396f97abe29d5b48afb7ba6be0ccf2e78b83a9e47f2cb389e09ff61031f901a4018505d21dba008405f5e10094c6a2ad8cc6e4a7e08fc37cc5954be07d499e76548094aeb54f22d60758431b5f7c9cf1552b9210d0a38bb8c452f28c170000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000000000000000000000000000080f89721378200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002786001922f9bd6300000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000f847f845824056a03475d7bcbd07782d6057f961824cb78df260f4c0c35287e10413fbc2eb7d5d93a02ab0a248eaf112b3e928252657330a390eea148104857aedf295dbffe3ca423a94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a05a58ec66cbe63a413210f80a7b965505c307f46107dc6cb4d09323bb265350b7a0158c61e53e86ea8f979f916ea7555171b2e4325317dc607e2969234244897b1531f902678201c18505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380948d23171fdeb6b107bf6372a1baf7bee06768d303b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd0000000000000000000000004a71d1753d278e1a64b2a5e5609dec3a66f99b050000000000000000000000000000000000000000000000000294aed1a0e82800da1f48559e48c67b9b8f101ca7bafb7065676263898c7da820c505732f7d724c0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041263a93ef7af64d2dce883ca1cbcf8a1294f76fceb890c1c9734ee24e052b9d8e5cf94fe2336b4a0f6735d11ccf57a05e3a949f0f491f74c1c7b69934694460ac1c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824056a06546095539ffdf15895bf6e93792906e030bb1bbaac7fdb13ae13f0e02b69d50a0112c71810f9094f08900da29b606c9f940f19ee3a37a3bc334a4f755e83b51f494c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0ad00996d41481911f2a007b433c29b1dfcbb413bd9f86feded2c1814ccbff9a4a023e181a45640d75551da10d576f1886c7e0004a230e418dfde620bc9303a4bd630f8b08202be8505d21dba008405f5e100940e29fe676e71038aa9496991a73ea609cb10ddb68901e5b8fa8fe2ac0000947af64163356ef28fcffebe1eb160e890a984282aa416cf3a3b000000000000000000000000c904e0ab77139f65c78b192bcf7266da85cc3343f847f845824055a0efe17561c016bd968720b851a1891694c537fdbffcac732d101338c7f0d989e9a04dcf56cd0ddba30913a31b416a6645de18e27051ef39a8cf12e203bf1df830f631f902678201c08505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f38094b20795b377c27220735c2762d3b07319200f5d07b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd0000000000000000000000001099ba6061bc434d4195b4f1ea85558179eb659c00000000000000000000000000000000000000000000000008230fc171c2e8001361610ce89c1cc7d4c8b525e0f99c9679f87504622bac247ecc88f39915cbc40000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041aa08aadbf4e22f03deb340eb7e3277c7a2e710550ac9b2d67e79b57d97afdc0f503c8b6b66b27c5b529c8dba736d594e4c394ee90f9a521910720a46f007ef0c1c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a04219c92c2633cd4632e6d6b14cb10f968a1cff2561f2de5f30a8996b08408ee0a0049d066612ef48c316ab1253b3e47ce16881ed62ebf7ed1ba45b06ed0e3e2e4194c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a019b35fb0e426a4116a197a07f1720aeaff021f2a50284aa4f7628f6d86e317e6a07a4c1393c155639712c4e228f151889ff9a82bbe1980dcdd3992b3f34c4c855930f8c5178505d21dba0083030d40945096db80b21ef45230c9e423c373f1fc9c0198dd8094005eb260ae04b9ebf8b843fc7fae5355d88d342bb844a9059cbb0000000000000000000000000d0707963952f2fba59dd06f2b425ace40b492fe00000000000000000000000000000000000000000000000116ea84fad84ee800f847f845824056a0c00b74ebe18c82817b45b4c39bb0610c774dca071990eac7a71fb46de82b94bda01685b4f8e7ab1ee6bba5293f90c74c9407ab4518fa2ffa4c884240a6b950c5e331f90124018505d21dba008405f5e100945096db80b21ef45230c9e423c373f1fc9c0198dd8094e28f1146d8ee27ba3c403109949dd0f8fcf8513cb844a9059cbb000000000000000000000000b894adc10b0583dd937987b4a7ca1afec53030890000000000000000000000000000000000000000000000000566c9588e8c7000f847f845824056a0c7288518a02f5ada63c68ae668556ce41df9f57e3787d57395f076b745784163a061e41b6a699ba6173ccb66deef3f94aba5993bfef651098bcdb7d1411b743ff594c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a0d8e22d0cf43ecb93fddcbaf7afa9d2a3e594d21852ac069eb1abde58425287bba01db2510059096f5f72fba5314701746f0ab5ebb173d0816b7f16e38cdbd52ba231f902678208fe8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380946f9b7fe1a3469723cd0fccf2cba8a7fb058400a1b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd00000000000000000000000019c0f2125849503effd881c6412ccd189d9814b900000000000000000000000000000000000000000000000089ce4e0241d68000869a7da7137e6c70b97d2939d4afc5664554fa6b756bd3e8c88d10113c35e77f0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041116ea36dad38e72e074a7ae545596966b4c23e2638397e5d0738922aa6274c0d595873ff4303ec769bd19690ce7f4522ed46dcbf10286453e8c8f84e467369d01b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a09548ed8a764acaae9b52fa8ee7c70d8e2c2ba8564d087268bdabd848f76df51ba034271696f9d1ca281d70da5b181caa4d4716d6a951986eaaafeade1d61722a7e94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a011da1174a293dd46b3a946fa48c94ed6c3316d2cdd9c30b82717138c03c03c88a0207084001d6b1a99c16c5af0ac77557dfc31fd9dec4ba879e29b23674331116331f901a4098505d21dba008405f5e10094c6a2ad8cc6e4a7e08fc37cc5954be07d499e76548094118a4a061c3b44b3ed7d73bc16a5f019858257b3b8c452f28c170000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd0000000000000000000000000000000000000000000000000adc8463eee1600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003541850d031c9cd100000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000f847f845824056a0785cc678f9e8e3d1202be001dd2a67010c8d291250148f9c0b68ead01384798ea02141cbea565df5c94d66d69a0f656406d2a2a911ce406c9e2ef40e44115b27d594c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0dbbbcf452f940acfd29eb6e7a92da8479fa4b83e95119004bcfb74ef3c5c2c89a04f2ffa4daded24c39b4290149e5dc5acdad83f1cf97892d41afeed9ac03bcd24f86e018505d21dba008252089486d2660297c82ac656715e00c979fb5ca65eecc58845dfb18d90b8340080824056a0afb6b15a9767709decfee1d80363b1b2e72257f725532b0dcba4ad8700a383a0a026c4ee3224d39ead531e4498d6b446e2eb3e36e613daab6021abbd2ec2943c94f86e028505d21dba008252089486d2660297c82ac656715e00c979fb5ca65eecc588667241b88680300080824056a0916d483d6e7ae0eda9acf8b1c964b074bc4184f9a2ad5f0ffca20250470ccfb5a03d7bf05097e3ef65054c439538db9fd27ceea6ef1a048e78e10d866b16dc29d831f90124158505d21dba008405f5e100945096db80b21ef45230c9e423c373f1fc9c0198dd80949eb865d7b842f82bbc94a49d38930fc2639254a7b844a9059cbb000000000000000000000000b21577b0c942fdd70fb92cbc513d9d7054142b820000000000000000000000000000000000000000000000000d9654cb08a84000f847f845824055a0508e9e10ca59f02beae7a22ff495e653f99b6aa7b9bffa9199faeb080745347ca00468231dab6b9287df965be617f0599376afef5f9273b78aba28d9b8b8e3e87b94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a06d8ca8a850f373a642f14631a86438681c03fada1b8ee5a8bb2cc47aa7507ab0a039cfea86781d877dfc40cbae89719263211d541751eaf5b107eafcf8e1eec65431f901c783011eee8505d21dba008419a1478094336c58eb84dc5d1bed1a600805d503e4a710f4708094059df703d963cbbf9e73150900e2094595a83711b8e42f11e9a8000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000404e666d332b517735637870764e5362344976474f706a3369657933785738734e72464661437171756c36774c67582f4f7147375a526d777a32476b6b334b6255f847f845824055a0b7d8c64ee4fd69bf63a433157dbe6cb83f364c96121ca123fe4c1104029adc6aa067457bc01d033ff4fbbcabe94ba5802e37edfce0175931124851203e74c1d4d09467abbf32db2bdc982b6b8782d8b4dea36c6115e5f847f845824055a04a0c850de4bce5f696fa141344b42dc6b500d0dba0c790b6acc0778a111f7ee7a07dcd1fdc3356d09b67f5cff1e789d012f7e7fd92c1b82694d277be9c6d07a40531f901c783011eef8505d21dba008419a1478094336c58eb84dc5d1bed1a600805d503e4a710f4708094059df703d963cbbf9e73150900e2094595a83711b8e42f11e9a8000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000404a5a4b50483431547a73352f365a4e317148664d595a7249337477657934626e676e4a454e5061497461304c67582f4f7147375a526d777a32476b6b334b6255f847f845824055a0f11124d50c96b7cd691e3205fa86a8eed1d934c7a1fd6d5fb2089b1d20317ab0a013a142330479b30a0fe781346ea5d73d553946abe380da18f8a3a83e9e927ca59467abbf32db2bdc982b6b8782d8b4dea36c6115e5f847f845824056a0a2c3117de73c54b349089129a33870bca2943552cd1df4e4d378eeb293ccbbdaa04205ca62b4f4f38ca64764fde4b45375ec6754bde8a8d273dc68feb4818ca00431f901c783011ef08505d21dba008419a1478094336c58eb84dc5d1bed1a600805d503e4a710f4708094059df703d963cbbf9e73150900e2094595a83711b8e42f11e9a80000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004047754c4c4d6142765939635272374c5566473879792b36344f616f474b496b38413676714b5335767579674c67582f4f7147375a526d777a32476b6b334b6255f847f845824055a046797aff5daf1c5f8028638e182faa4b6e34272ed06bb5959b875f7c46f9a257a03d237173b0eb7af541d04f07ba8040ac361409cca4b66ed0bf18d79a1015d2559467abbf32db2bdc982b6b8782d8b4dea36c6115e5f847f845824055a0340b795a958d525a89a902bb670e1f75fd83408c552098b7605117fc5df97348a067f43ca1c4c681a87ba61de63265833fcc606f83ecded2ea7a133005efd9188731f901c683011ef18505d21dba008419a1478094336c58eb84dc5d1bed1a600805d503e4a710f4708094059df703d963cbbf9e73150900e2094595a83711b8e42f11e9a80000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004066385870565541764c66416e514557614748552b6544766237776f4b7561506a46575550795076783071344c67582f4f7147375a526d777a32476b6b334b6255f846f844824055a0f7381ba9d1ab61b424f435e449b5ac6fd536fe47ef6190562bd533b9cebc7fdd9f2ef20ee45b8db64a29f28a004840bcbd318f6b06f7d035d143e90e9261d4449467abbf32db2bdc982b6b8782d8b4dea36c6115e5f847f845824056a0fd099cb76e4d69195c0b681081bb405a561aadebcbc73cea81451dd3ce98953ca03efe60805d4d8f2a2cff9ce5d906ea2224b4fbc1d424043b476c3eb4777d716231f901c783011ef28505d21dba008419a1478094336c58eb84dc5d1bed1a600805d503e4a710f4708094059df703d963cbbf9e73150900e2094595a83711b8e42f11e9a80000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000004033665842684271437a73744b6948646c754d4977376d31396365476d653446742f4a6c6a374d366c684f554c67582f4f7147375a526d777a32476b6b334b6255f847f845824055a001d603c1bdfc471e28cc55ef3d03b4ffbe8a7f8b2323c5938643820b44f3f942a04340e45298e34be77d370404dbace8a81c156932de0dcdae4279cae67e9e8a7f9467abbf32db2bdc982b6b8782d8b4dea36c6115e5f847f845824056a0e93dc7fc4974bbe2f668a427ece1ff52317235bacfe7a3cd9fa6f343962d7c39a0585827f1af2d5aa6ef889e748089f5efb9fdb11a8711b9f94ec85eee947eacc131f902678201be8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f38094ece9d0fbd622220a752dbe919fafcb347f9fb36bb90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000dcc3e29290514dce065aadc64ea2e29680781da50000000000000000000000000000000000000000000000000d84ba10a0ddc00031fbdcd50e4239a320945a9e3b8ce98832248cd53b4d1fe9c955c7808806a9810000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000410d85ee75646b48fcfd01965ebaab9cf0f0442adfa469ea640feb2cf0fb67ddec15b63151026028c2f865a4bc4ed2d54e7a252c83134476ba6ad1f78224a96de01c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824056a007d0f0b5191dd3bba38997d7d6dd2b71a891ba65ab1051fb52f2a029d4ca9930a034acce7f992d50038eba34b5e212822f86bb97cf2a1a665c6bee25930a7bb91d94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a038c270b51e8ee02e63338f2d0b0a565229a790df4911320b3c981d234e10f7c0a04b85acbb9492335be0085b10396dd2c03ab3c7e2e729b27f281bdc418651a01831f902678201be8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f3809449b7e68e4bc741854b045b9f6465c40ca12a0226b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000c279e01e405173d6d78e090ff0cad21ffb1a32330000000000000000000000000000000000000000000000000acb9ed5645420002b6178c376406c3235d1ffff6bf0799d3ed1f8ef2823666d23f2ae41962a686e0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000414c6be52e540f7c75deff1be9996bb6098395012625026f4ef32ab08fd5bbdb961b3beec681567c50e4b6e9834f6ba087bff094a286de24157cc2ccbd3d5244a31b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a00d9c43355f40c7768d511a8ea195e3af6252ee8dcdc52c06e28669446480d4c9a06bede4bdb488fda709fe000ba73c95f6d25f78f65c54be0d2c20de3cbf77f42d94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a05e542705547665466a5c1f3622c2f368100c783b53e7b88dfe477d4039ca3759a017886f5f2b84237395a9f066d0341ceab20a45fcfac05540f6bad45f0a9bb711f901ef820c088505d21dba00833d0900940a530b3209af923735ddd02872a4994f15bcfbc280b9018443076c9a000000000000000000000000000000000000000000000278738640af254aaaaa0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c6a2ad8cc6e4a7e08fc37cc5954be07d499e765400000000000000000000000002cbe46fb8a1f579254a9b485788f2d86cad51aa00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001824055a0e0ea61478710af76cf8bef71ced1f7b56f9256d1138b2f5766bd3f6b9d8c9bc5a033ffb9e2bd8325a482df397704e62bf70c8fd02c38b1fbcdf2db9f5f48eba57431f902678209008505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f3809407cfebef2d3d69592ca6f8a6a7a4319344470258b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd0000000000000000000000005c1a821b28da8b6e5d3a361262caaee0cc36191b000000000000000000000000000000000000000000000000488bbd5d16758000793ff56cb927fd966e548fea39a832ee98cd30d06e14b754eab85ececdbe861d0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041e4d99d3c951a99e0e0279a0ed6912bc67ee977ee61ad4f7b27317d93abad5b7e14f0c92c7d9f9ab097d6f8cb97c7cef5c0d7c308effc641a8806e00b305c23bb1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824056a0b6e2c1288e1d9911509bbbd4950d96319551d10074bda71392265932f3e9479ba023696da341ffcae3d5e5d99180eccb8627bf6f63889cae81769768ada00df99c94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a08af9ba639e6e48abd2fba72fe4b6144b704e39ee4c0cd81e906e692985422d52a02d5a6bb6a7a0a35b19487aecddfff6e7ebd83d80d2af85562536a0b31112281c31f901c58202728505d21dba0083419ce094dcd62c57182e780e23d2313c4782709da85b9d6c80947a0b4d87a30008bc600d568287a27d2a2eed255eb8e4eb795549000000000000000000000000336c58eb84dc5d1bed1a600805d503e4a710f47000000000000000000000000000000000000000000000000029a2241af62c000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000041014434556471723043377a4f4535474e49305165595064533631776d444238703949686934454a6553646b634c67582f4f7147375a526d777a32476b6b334b625500000000000000000000000000000000000000000000000000000000000000f847f845824056a098526d1ca6890a18acd0264e76250bb9d0641685439fbf105bc52fec06bb6080a043cf257f4197f3416a481d219f33319e27483bc3dca02bc1996af13a17d998b79467abbf32db2bdc982b6b8782d8b4dea36c6115e5f847f845824055a0dd227698ccd76be97ce28006dd2d84174f93009cb275810e6af0988620626b1ca064aed5b78327da104a5b6194230060fc597a2567fe5f84ee0a72ce897610fd9231f901c58202738505d21dba0083419ce094dcd62c57182e780e23d2313c4782709da85b9d6c80947a0b4d87a30008bc600d568287a27d2a2eed255eb8e4eb795549000000000000000000000000336c58eb84dc5d1bed1a600805d503e4a710f4700000000000000000000000000000000000000000000000001bc16d674ec8000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000041012f76476d2f577a4f487634504163676d70674e4a4b6a64466b5565544a765337397655587a424f374e6e514c67582f4f7147375a526d777a32476b6b334b625500000000000000000000000000000000000000000000000000000000000000f847f845824056a07055afee730e45ee175e1baf69d04b89a0e0dd36f7bb8748336edd462c93c67da05e88c3a5da3cdec7956cf8cf9be2729b86961c68baa5c846b9d94f7a3ec5774f9467abbf32db2bdc982b6b8782d8b4dea36c6115e5f847f845824056a010b98fc7fed096b6586a97ef0d14d595f62b6ba40c088a15613b217733234234a0061805a46ed4120ee29dbfebd26bd2bed489e717a9462339d627c9b6656a8b9830f8c5018505d21dba0083030d40945096db80b21ef45230c9e423c373f1fc9c0198dd8094b97a579adb2f35fbe0e6d1f238de4a7e46ba5ea2b844a9059cbb0000000000000000000000000d0707963952f2fba59dd06f2b425ace40b492fe000000000000000000000000000000000000000000000001862b2f1ce8b1a800f847f845824055a00e46c121c444acaa15b2e137954b8cc6d61d842e381914123e61b0ed1cb9b622a067b694c09d86bd5ef4b4b52c6f5d08dce2507909bc171e731686a90343e057b5f87481838505d21dba00826e0e94fd844c2fca5e595004b17615f891620d1cb9bbb2890168d28e3f0028000084d0e30db0824056a0aaa4f9990057c37145ec58c38aaab1009189b2d386211118e09fbc3b32238927a056c4fda051dd031878f231e685fc00426e7a9ea98cdb82d52f998e136a8beed931f902678201c08505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380942042e4698bc763a7d232e9c5a82e17798c0f6a40b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd0000000000000000000000009cdaeae06e58eaf6a3f7c8a8f1c5d902cb72d35800000000000000000000000000000000000000000000000012b40ba6e9773000a283a6882d4d90e9072967ce3c40cefb864007904e92c370f9cb1728d7dd9ee50000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000414427ce2d5e7da5fb9e3b6020952af05aaa6b611f84e996396bae14605fe40ab6509a61737c9c50ad7a9d91f40fb4ece85f100ca089f26b470b720336e8817f731c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a02728550e047d35e8f12c566013a42f1610ca860fa58de5c5d4fd972964dd6f51a04ce878cf7592c9dd5eac8fa4f114a98633a5927767c5bcc7d7c4595660a650aa94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0e4b993d10b3e92d1702dfce0fbfc29a205a1891f8ba159c5899358534c67a32ca0107f2e6e8eb485cb9eb6e6c532561f81b5ff4dc38b0fdd0e3db0d29f28a254f330f8c5048505d21dba0083030d40945096db80b21ef45230c9e423c373f1fc9c0198dd8094fb8d1584306c91bbd7816ed11f36fc6fcffc6b93b844a9059cbb0000000000000000000000000d0707963952f2fba59dd06f2b425ace40b492fe000000000000000000000000000000000000000000000001032a0745845ce000f847f845824055a001700713af395cd2ef2e5e44d935f21c83aa3691aa7053fce2387cd367784596a07df1c246d34062a71577cf9c358904bca337201fd0d697459e1284b96dd4b38830f8c5078505d21dba0083030d40945096db80b21ef45230c9e423c373f1fc9c0198dd809486b18f68d6cda1fa0afc0366dfa0df010934772fb844a9059cbb0000000000000000000000000d0707963952f2fba59dd06f2b425ace40b492fe000000000000000000000000000000000000000000000003cb71f51fc5580000f847f845824055a0f56f2db775dee7ff34b202cb060f61bc42920f2022c459630753add01c1992f2a0236899fbedeb983b3ff579982f05802421ce739a17664e6ea7f9416854dd44f031f902678201ba8505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380947520a2bf8ae07f345787712f6a144e0d3be7bf26b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000d08a38f7b8f6c1ebb214b5fc049bec59c429e97200000000000000000000000000000000000000000000000002ae62605a9b0000338c74e56e62558cef19ce9c6ab1029d622c2e14c06b09f656ea7b0f2dc5e1ff0000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001600000000000000000000000000000000000000000000000000000000000000041fb4542a748aa62867c71149c4fd01c9fd0833a1209d73e549b7990a4762937075f5bf8a1386c131ea6bfb09a8c772305850e6b23e306fd6621b619eca47c31aa1c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a08c2fbee8ac5bd849e57107e3a96e2a4f975581aef7dc70fab33d4f151ca92d1ba009fa9fad65fd0083957ac8494d35ae405a5af787833a8b12586f78ff00d7e7bf94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a0de0d5832e60b766b98305a86129e5f46f69681d09bc687f6091b595c708e0265a06539510ef1cdea54180b34f69c30d588f9c1a5918707918c24896137b5fabfca31f902678201c18505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f380941e26a9a54c913aa17618cb9cef6ccab5b69cdb51b90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000e28f1146d8ee27ba3c403109949dd0f8fcf8513c0000000000000000000000000000000000000000000000000566c9588e8c7000650bbaf559120e0f19ed2e3456abc51718f0a8280dfea7740d997395c810cbe90000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000418bf0333992d78aaa3e7d4cffeb25e1b45e40d43ba381b0a5d4431bb5a9bb06e260cc1e485facb68cef52f018de324a75bb9fdf4629aebf62495d4201bb87980e1c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a062dd342288f8f937e81ea58bb0f443b870b7c2464e0f3e42f0b08adc9a7e7f5ca06f00bd238124cae7dbd3817c5ae4d77dafd47b7aea0cff35e101a40b8faea95e94c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824056a0713ab17515d74068f5ac2ad1b6e6c63a45d4c1414622a0c7cd1756b9d3372143a02943f7df82db78c6ae28e7e6e6babc37d26e19bd2700bcd3f99fdf85a9b8613531f902678201c48505d21dba008405f5e100943cb3890004e8f5a6885c1d8d359e8c2946b504f38094b63d619c261bdea4f61948f413bf9c51ae47405ab90184be966e4e0000000000000000000000005096db80b21ef45230c9e423c373f1fc9c0198dd000000000000000000000000aef4ea7cb28c74f3b4dc7ac54de47ce9189b1e8900000000000000000000000000000000000000000000000002fac8c97f1b5800b3e3eb27f738d3d40431435a71f2c380a443ae70a9890fd1b4ec5b5642077fb20000000000000000000000000000000000000000000000000011c37937e0800000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000004109092646e042913f6ad3a1c8eb950f839cb40ad6b218a9f065369534f06dda5135953c4b0bceaedf52cd03a53c374ca4af5fa7e8d24b917bbfd62562ccce94a61c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f847f845824055a047fb7561d12215fb9dc674836a0465fdc753263b5646cef647920a7db418f79ea06713ce45f1474fdaf810ce0b6992fb66ab570a6d7b21b09721ca2de96fb9d62894c85d740a01dacefaf4c2f9e6a6e35c6255a807a2f847f845824055a00fd26a77bd418f68af4082f97242f1b83f93ff732ffd936e0535874a974424fba03f5023d4a2db70778ad8e636ffcf11a57471b081e69691f113809d1a444208f730f8c782034e8505d21dba008305e666942c127c4c43cbfaaaf217444cc1e1c523584805118094fd4cd0c501ac767ea3d91f8daf5c701350290fcdb84499e68671000000000000000000000000fd4cd0c501ac767ea3d91f8daf5c701350290fcd00000000000000000000000000000000000000000000011d9fb083d39a117000f847f845824056a0ced39afc2aa7c18429470806325b0910bdf2fc9537f700d7a623f4d462a79dbea0549b86f0240c491e646e838fc9266f79560919402dd0aa98a7aaa5560825acaa"

	blk := types.Block{}
	rlp.DecodeBytes(common.FromHex(blockRlp), &blk)
	fmt.Println(blk.String())
}

func Test22(t *testing.T) {
	tx := types.Transaction{}
	err := json.Unmarshal([]byte(`
{
"blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
"blockNumber": "0x0",
"feePayer": "0x6d8202b8da35d424075984d4bb2fd2d455fc2047",
"feePayerSignatures": [{
"R": "0xbf3a6939ab95e63c29814c1eed9068d6571180bb512bb1bd64e8d71c49ea6895",
"S": "0x30cc153b0899b859fa41b95e66a1140233ac72a2c851a4cb2109cd83f12a2475",
"V": "0x4056"
  }],
"from": "0x2c4eb6b41b1cd0d1c3d3fc82ce6a3c4d7408f9c8",
"gas": "0xf4240",
"gasPrice": "0x5d21dba00",
"hash": "0xc7dd14f8f3c511c267c8c132898969be13ab7847abda9d8b38b396bdfd6e5536",
"key": "0x05f8f0b84e04f84b02f848e301a103271649fed74afde33e5702220cf7f9e91dca83bd6496f94c4c9c758fd0ab51e6e301a1039d5ab11c66ebee1e0c516c25b948a0a52c643f9b3f5d9a42ad05aae725eca794b84e04f84b01f848e301a103271649fed74afde33e5702220cf7f9e91dca83bd6496f94c4c9c758fd0ab51e6e301a1039d5ab11c66ebee1e0c516c25b948a0a52c643f9b3f5d9a42ad05aae725eca794b84e04f84b02f848e301a103271649fed74afde33e5702220cf7f9e91dca83bd6496f94c4c9c758fd0ab51e6e301a1039d5ab11c66ebee1e0c516c25b948a0a52c643f9b3f5d9a42ad05aae725eca794",
"nonce": "0x5",
"senderTxHash": "0x7d7f814fc4dd83485190468e8794cb0fdece86c488456213fae33975d6300ce8",
"signatures": [{
"R": "0x8c94de0f82ba9bf7495913d7ac5cb9fc2abbfb9b59b36ed849b7030524f81c21",
"S": "0x52334674bcc58d112ec963206e0c16b89bc5546ef8e0f0308e309ff98429d070",
"V": "0x4056"
  }],
"transactionIndex": "0x0",
"type": "TxTypeFeeDelegatedAccountUpdate",
"typeInt": 33
}
`), &tx)
	if err != nil {
		panic(err)
	}
	signer := types.NewEIP155Signer(big.NewInt(8217))
	pubkey, _ := types.SenderPubkey(signer, &tx)
	fmt.Println(crypto.PubkeyToAddress(*pubkey[0]).String())
	fmt.Println(tx.String())
}