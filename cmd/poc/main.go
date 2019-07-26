package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/blockchain/types/accountkey"
	"github.com/klaytn/klaytn/client"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/console"
	"github.com/klaytn/klaytn/crypto"
	"github.com/klaytn/klaytn/params"
	"math/big"
	"os"
	"time"
)

type TestRoleBasedAccountType struct {
	Addr       common.Address
	TxKeys     []*ecdsa.PrivateKey
	UpdateKeys []*ecdsa.PrivateKey
	FeeKeys    []*ecdsa.PrivateKey
	Nonce      uint64
	AccKey     accountkey.AccountKey
}

func getPK(k string) *ecdsa.PrivateKey {
	str, err := console.Stdin.PromptPassword(k+":")
	if err != nil {
		panic(err)
	}

	if len(str) > 0 {
		pk1, err := crypto.HexToECDSA(str)
		if err != nil {
			fmt.Println("Please remove preceding 0x if exists.")
			panic(err)
		}

		return pk1
	}

	pk1, err := crypto.GenerateKey()
	if err != nil {
		panic(err)
	}

	return pk1
}

func getEndpoint() string {
	str := os.Getenv("ENDPOINT")
	if len(str) == 0 {
		return "http://localhost:8551"
	}
	return str
}

func main() {
	fmt.Println("Please insert private key without preceding 0x.")
	fmt.Println("If you insert an empty string, a private key will be generated.")
	pk1 := getPK("PK1")
	pk2 := getPK("PK2")
	pk3 := getPK("PK3")

	returnAddrStr, err := console.Stdin.Prompt("ReturnAddr:")
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	cli, err := client.Dial(getEndpoint())
	if err != nil {
		panic(err)
	}

	chainId, err := cli.ChainID(ctx)
	if err != nil { panic(err) }

	returnAddr := common.HexToAddress(returnAddrStr)
	signer := types.NewEIP155Signer(chainId)
	gasPrice := new(big.Int).SetUint64(25 *params.Ston)

	PoCAccount := &TestRoleBasedAccountType{
		Addr:       crypto.PubkeyToAddress(pk1.PublicKey),
		TxKeys:     []*ecdsa.PrivateKey{pk2},
		UpdateKeys: []*ecdsa.PrivateKey{pk2},
		FeeKeys:    []*ecdsa.PrivateKey{pk3},
		Nonce:      uint64(0),
		AccKey:     accountkey.NewAccountKeyRoleBasedWithValues(accountkey.AccountKeyRoleBased{
			accountkey.NewAccountKeyPublicWithValue(&pk2.PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&pk2.PublicKey),
			accountkey.NewAccountKeyPublicWithValue(&pk3.PublicKey),
		}),
	}

	{
		acc, err := cli.GetAccount(ctx, PoCAccount.Addr)
		if err != nil {
			panic(err)
		}
		fmt.Println("[Before AccountUpdate] ", PoCAccount.Addr.String(), ":", acc)
	}

	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      PoCAccount.Nonce,
			types.TxValueKeyFrom:       PoCAccount.Addr,
			types.TxValueKeyGasLimit:   uint64(81000),
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: PoCAccount.AccKey,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		if err != nil { panic(err) }

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{pk1})
		if err != nil { panic(err) }

		fmt.Println("1. Updating account key with {PK2, PK2, PK3}")
		txHash, err := cli.SendRawTransaction(ctx, tx)
		if err != nil { panic(err) }
		fmt.Println("txHash = ", txHash.String())

		PoCAccount.Nonce++
		time.Sleep(3 * time.Second)
		{
			r, err := cli.TransactionReceiptRpcOutput(ctx, txHash)
			if err != nil { panic(err) }
			s, err := json.MarshalIndent(r, "", "  ")
			if err != nil { panic(err) }
			fmt.Println(string(s))
		}
	}

	{
		acc, err := cli.GetAccount(ctx, PoCAccount.Addr)
		if err != nil { panic(err) }
		fmt.Println("[After AccountUpdate] ", PoCAccount.Addr.String(), ":", acc)
	}


	{
		amount := new(big.Int).SetUint64(10000)
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:    PoCAccount.Nonce,
			types.TxValueKeyFrom:     PoCAccount.Addr,
			types.TxValueKeyTo:       PoCAccount.Addr,
			types.TxValueKeyAmount:   amount,
			types.TxValueKeyGasLimit: uint64(21000),
			types.TxValueKeyGasPrice: gasPrice,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeValueTransfer, values)
		if err != nil { panic(err) }

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{pk3})
		if err != nil { panic(err) }

		fmt.Println("")
		fmt.Println("2. Transferring value from ", PoCAccount.Addr.String(), "to", PoCAccount.Addr.String(), "signed by pk3")
		_, err = cli.SendRawTransaction(context.Background(), tx)
		fmt.Println(err)
		if err.Error() != types.ErrInvalidSigSender.Error() {
			panic(err)
		}
	}

	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      PoCAccount.Nonce,
			types.TxValueKeyFrom:       PoCAccount.Addr,
			types.TxValueKeyGasLimit:   uint64(81000),
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: PoCAccount.AccKey,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		if err != nil { panic(err) }

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{pk3})
		if err != nil { panic(err) }

		fmt.Println("")
		fmt.Println("3. Updating account key with {PK2, PK2, PK3} signed by pk3")
		_, err = cli.SendRawTransaction(context.Background(), tx)
		fmt.Println(err)
		if err.Error() != types.ErrInvalidSigSender.Error() {
			panic(err)
		}
	}

	{
		amount := new(big.Int).SetUint64(10000)
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:    PoCAccount.Nonce,
			types.TxValueKeyFrom:     PoCAccount.Addr,
			types.TxValueKeyTo:       PoCAccount.Addr,
			types.TxValueKeyAmount:   amount,
			types.TxValueKeyGasLimit: uint64(21000),
			types.TxValueKeyGasPrice: gasPrice,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeValueTransfer, values)
		if err != nil { panic(err) }

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{pk1})
		if err != nil { panic(err) }

		fmt.Println("")
		fmt.Println("4. Transferring value from ", PoCAccount.Addr.String(), "to", PoCAccount.Addr.String(), "signed by pk1")
		_, err = cli.SendRawTransaction(context.Background(), tx)
		fmt.Println(err)
		if err.Error() != types.ErrInvalidSigSender.Error() {
			panic(err)
		}
	}

	{
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:      PoCAccount.Nonce,
			types.TxValueKeyFrom:       PoCAccount.Addr,
			types.TxValueKeyGasLimit:   uint64(81000),
			types.TxValueKeyGasPrice:   gasPrice,
			types.TxValueKeyAccountKey: PoCAccount.AccKey,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeAccountUpdate, values)
		if err != nil { panic(err) }

		err = tx.SignWithKeys(signer, []*ecdsa.PrivateKey{pk1})
		if err != nil { panic(err) }

		fmt.Println("")
		fmt.Println("5. Updating account key with {PK2, PK2, PK3} signed by pk1")
		_, err = cli.SendRawTransaction(context.Background(), tx)
		fmt.Println(err)
		if err.Error() != types.ErrInvalidSigSender.Error() {
			panic(err)
		}
	}

	{
		amount := new(big.Int).Div(new(big.Int).SetUint64(9 * params.KLAY), big.NewInt(10))
		values := map[types.TxValueKeyType]interface{}{
			types.TxValueKeyNonce:    PoCAccount.Nonce,
			types.TxValueKeyFrom:     PoCAccount.Addr,
			types.TxValueKeyFeePayer: PoCAccount.Addr,
			types.TxValueKeyTo:       returnAddr,
			types.TxValueKeyAmount:   amount,
			types.TxValueKeyGasLimit: uint64(31000),
			types.TxValueKeyGasPrice: gasPrice,
		}
		tx, err := types.NewTransactionWithMap(types.TxTypeFeeDelegatedValueTransfer, values)
		if err != nil { panic(err) }

		err = tx.SignWithKeys(signer, PoCAccount.TxKeys)
		if err != nil { panic(err) }

		err = tx.SignFeePayerWithKeys(signer, PoCAccount.FeeKeys)
		if err != nil { panic(err) }

		fmt.Println("")
		fmt.Println("6. Execution of FeeDelegatedValueTransfer with pk1(RoleTransaction) and pk3(RoleFeePayer)")
		txHash, err := cli.SendRawTransaction(context.Background(), tx)
		if err != nil { panic(err) }
		fmt.Println("txHash = ", txHash.String())

		time.Sleep(3 * time.Second)
		{
			r, err := cli.TransactionReceiptRpcOutput(ctx, txHash)
			if err != nil { panic(err) }
			s, err := json.MarshalIndent(r, "", "  ")
			if err != nil { panic(err) }
			fmt.Println(string(s))
		}
	}
}
