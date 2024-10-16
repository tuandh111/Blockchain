package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"Blockchain/core"
	"Blockchain/crypto"
	"Blockchain/network"
	"Blockchain/types"
	"Blockchain/util"
)

func main() {
	validatorPrivKey := crypto.GeneratePrivateKey()
	fmt.Println("private key: ", validatorPrivKey.PublicKey())
	localNode := makeServer("LOCAL_NODE", &validatorPrivKey, ":3000", []string{":4000"}, ":9000")
	go localNode.Start()
	toValidatorPrivKey := crypto.GeneratePrivateKey()
	fmt.Println("to private key: ", toValidatorPrivKey.PublicKey())
	remoteNode := makeServer("REMOTE_NODE", &toValidatorPrivKey, ":4000", []string{":5000"}, ":9001")
	go remoteNode.Start()
	//
	remoteNodeB := makeServer("REMOTE_NODE_B", nil, ":5000", nil, "")
	go remoteNodeB.Start()

	go func() {
		time.Sleep(11 * time.Second)

		lateNode := makeServer("LATE_NODE", nil, ":6000", []string{":4000"}, "")
		go lateNode.Start()
	}()

	time.Sleep(1 * time.Second)
	//
	/*	if err := sendTransaction(validatorPrivKey, toValidatorPrivKey); err != nil {
		panic(err)
	}*/
	/*	time.Sleep(1 * time.Second)
		if err := sendTransaction(validatorPrivKey, toValidatorPrivKey); err != nil {
			panic(err)
		}
		//
		collectionOwnerPrivKey := crypto.GeneratePrivateKey()
		collectionHash := createCollectionTx(collectionOwnerPrivKey)
		//
		txSendTicker := time.NewTicker(1 * time.Second)
		go func() {
			for i := 0; i < 20; i++ {
				nftMinter(collectionOwnerPrivKey, collectionHash)

				<-txSendTicker.C
			}
		}()*/

	select {}
}

func sendTransaction(privKey crypto.PrivateKey, toPrivKey crypto.PrivateKey) error {
	tx := core.NewTransaction(nil)
	tx.From = privKey.PublicKey()
	tx.To = toPrivKey.PublicKey()
	tx.Data = []byte("chuyển khoản")
	tx.Value = 6699

	buf := &bytes.Buffer{}

	if err := tx.Encode(core.NewGobTxEncoder(buf)); err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", "http://localhost:9000/tx", buf)
	if err != nil {
		panic(err)
	}
	client := http.Client{}
	_, err = client.Do(req)

	return err
}

func makeServer(id string, pk *crypto.PrivateKey, addr string, seedNodes []string, apiListenAddr string) *network.Server {
	opts := network.ServerOpts{
		APIListenAddr: apiListenAddr,
		SeedNodes:     seedNodes,
		ListenAddr:    addr,
		PrivateKey:    pk,
		ID:            id,
	}

	s, err := network.NewServer(opts)
	if err != nil {
		log.Fatal(err)
	}

	return s
}

func createCollectionTx(privKey crypto.PrivateKey) types.Hash {
	tx := core.NewTransaction(nil)
	tx.TxInner = core.CollectionTx{
		Id:       200,
		MetaData: []byte("chicken and egg collection!"),
	}
	tx.From = privKey.PublicKey()
	tx.Sign(privKey)

	buf := &bytes.Buffer{}
	if err := tx.Encode(core.NewGobTxEncoder(buf)); err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", "http://localhost:9000/tx", buf)
	if err != nil {
		panic(err)
	}

	client := http.Client{}
	_, err = client.Do(req)
	if err != nil {
		panic(err)
	}

	return tx.Hash(core.TxHasher{})
}

func nftMinter(privKey crypto.PrivateKey, collection types.Hash) {
	metaData := map[string]any{
		"power":  8,
		"health": 100,
		"color":  "green",
		"rare":   "yes",
	}

	metaBuf := new(bytes.Buffer)
	if err := json.NewEncoder(metaBuf).Encode(metaData); err != nil {
		panic(err)
	}

	tx := core.NewTransaction(nil)
	tx.From = privKey.PublicKey()
	tx.TxInner = core.MintTx{
		Fee:             200,
		NFT:             util.RandomHash(),
		MetaData:        metaBuf.Bytes(),
		Collection:      collection,
		CollectionOwner: privKey.PublicKey(),
	}
	tx.Sign(privKey)

	buf := &bytes.Buffer{}
	if err := tx.Encode(core.NewGobTxEncoder(buf)); err != nil {
		panic(err)
	}
	req, err := http.NewRequest("POST", "http://localhost:9000/tx", buf)
	if err != nil {
		panic(err)
	}

	client := http.Client{}
	_, err = client.Do(req)
	if err != nil {
		panic(err)
	}
}
