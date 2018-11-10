package main

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"

	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	validatorContract "github.com/ethereum/go-ethereum/contracts/validator"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

func main() {
	fmt.Println("test")
	// Validator Smart Contract Code
	pKey, _ := crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr := crypto.PubkeyToAddress(pKey.PublicKey)
	contractBackend := backends.NewSimulatedBackend(core.GenesisAlloc{addr: {Balance: big.NewInt(1000000000)}})
	transactOpts := bind.NewKeyedTransactor(pKey)

	addr = crypto.PubkeyToAddress(pKey.PublicKey)
	signers := []common.Address{addr}

	validatorCap := new(big.Int)
	validatorCap.SetString("50000000000000000000000", 10)
	validatorCaps := []*big.Int{validatorCap}

	validatorAddress, _, err := validatorContract.DeployValidator(transactOpts, contractBackend, signers, validatorCaps, addr)
	if err != nil {
		fmt.Println("Can't deploy root registry")
	}
	contractBackend.Commit()

	d := time.Now().Add(1000 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	code, _ := contractBackend.CodeAt(ctx, validatorAddress, nil)
	fmt.Println("contract code", common.ToHex(code))

	storage := make(map[common.Hash]common.Hash)
	f := func(key, val common.Hash) bool {
		decode := []byte{}
		trim := bytes.TrimLeft(val.Bytes(), "\x00")
		rlp.DecodeBytes(trim, &decode)
		storage[key] = common.BytesToHash(decode)
		fmt.Println("DecodeBytes", "value", val.String(), "decode", storage[key].String())
		return true
	}
	contractBackend.ForEachStorageAt(ctx, validatorAddress, nil, f)
}
