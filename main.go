package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"

	"context"
	"encoding/json"
	"io/ioutil"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	validatorContract "github.com/ethereum/go-ethereum/contracts/validator"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

type Keys struct {
	Owner       string   `json:"owner"`
	Masternodes []string `json:"masternodes"`
}

func main() {
	jsonFile, err := os.Open("keys.json")
	if err != nil {
		fmt.Println(err)
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var result Keys
	json.Unmarshal([]byte(byteValue), &result)

	keys := result.Masternodes
	owner := result.Owner
	// Validator Smart Contract Code

	signers := []common.Address{}
	validatorCap := new(big.Int)
	validatorCap.SetString("50000000000000000000000", 10)
	validatorCaps := []*big.Int{}

	for _, key := range keys {
		pKey, _ := crypto.HexToECDSA(key)
		addr := crypto.PubkeyToAddress(pKey.PublicKey)
		addr = crypto.PubkeyToAddress(pKey.PublicKey)
		signers = append(signers, addr)
		validatorCaps = append(validatorCaps, validatorCap)
	}

	pKey, _ := crypto.HexToECDSA(owner)
	addr := crypto.PubkeyToAddress(pKey.PublicKey)
	addr = crypto.PubkeyToAddress(pKey.PublicKey)

	contractBackend := backends.NewSimulatedBackend(core.GenesisAlloc{addr: {Balance: big.NewInt(1000000000)}})
	transactOpts := bind.NewKeyedTransactor(pKey)

	validatorAddress, _, err := validatorContract.DeployValidator(transactOpts, contractBackend, signers, validatorCaps, addr)
	if err != nil {
		fmt.Println("Can't deploy root registry")
	}
	contractBackend.Commit()

	d := time.Now().Add(1000 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), d)
	defer cancel()
	code, _ := contractBackend.CodeAt(ctx, validatorAddress, nil)
	fmt.Println(common.ToHex(code))

	storage := make(map[common.Hash]common.Hash)
	f := func(key, val common.Hash) bool {
		decode := []byte{}
		trim := bytes.TrimLeft(val.Bytes(), "\x00")
		rlp.DecodeBytes(trim, &decode)
		storage[key] = common.BytesToHash(decode)
		fmt.Println(val.String(), storage[key].String())
		return true
	}
	contractBackend.ForEachStorageAt(ctx, validatorAddress, nil, f)
}
