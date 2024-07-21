package api

import (
	"Blockchain/crypto"
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"github.com/labstack/echo/v4/middleware"
	"net/http"
	"strconv"

	"Blockchain/core"
	"Blockchain/types"
	"github.com/go-kit/log"
	"github.com/labstack/echo/v4"
)

type TxResponse struct {
	TxCount uint
	Hashes  []string
}

type APIError struct {
	Error string
}

type Block struct {
	Hash          string
	Version       uint32
	DataHash      string
	PrevBlockHash string
	Height        uint32
	Timestamp     int64
	Validator     string
	Signature     string

	TxResponse TxResponse
}

type ServerConfig struct {
	Logger     log.Logger
	ListenAddr string
}
type PrivateKeyResponse struct {
	Publickey string `json:"Publickey"`
}
type PatientInfo struct {
	FullName        string `json:"fullName"`
	Age             int    `json:"age"`
	Gender          string `json:"gender"`
	Address         string `json:"address"`
	PhoneNumber     string `json:"phoneNumber"`
	Email           string `json:"email"`
	MedicalHistory  string `json:"medicalHistory"`
	Diagnosis       string `json:"diagnosis"`
	TreatmentPlan   string `json:"treatmentPlan"`
	NextAppointment string `json:"nextAppointment"`
}

type TransactionRequest struct {
	PatientInfo PatientInfo `json:"patientInfo"`
	Id          uint64      `json:"id"`
}
type TransactionMessageRequest struct {
	Message string `json:"Message"`
	Id      uint64 `json:"Id"`
}

type Server struct {
	txChan chan *core.Transaction
	ServerConfig
	bc      *core.Blockchain
	privKey *crypto.PrivateKey
}
type Message struct {
	Message string `json:"Message"`
}

func NewServer(cfg ServerConfig, bc *core.Blockchain, txChan chan *core.Transaction, privKey *crypto.PrivateKey) *Server {
	return &Server{
		ServerConfig: cfg,
		bc:           bc,
		txChan:       txChan,
		privKey:      privKey,
	}
}

func (s *Server) Start() error {
	e := echo.New()
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
	}))
	e.GET("/block/:hashorid", s.handleGetBlock)
	e.GET("/tx/:hash", s.handleGetTx)
	e.POST("/tx", s.handlePostTx)
	e.GET("/txs", s.handleGetAllTxs)
	e.GET("/tx/withinner", s.handleGetTransactionsWithTxInner)
	e.GET("/tx/withoutinner", s.handleGetTransactionsWithoutTxInner)
	e.GET("/priv", s.handleGeneratePrivateKey)
	e.POST("/create-and-send-tx", s.handleCreateAndSendTx)
	e.POST("/create-and-send-nft", s.handleCreateAndSendNFT)
	e.GET("/tx/block/:txhash", s.handleGetBlockForTx)
	e.GET("/blockchain", s.getBlockChain)
	return e.Start(s.ListenAddr)
}
func (s *Server) getBlockChain(c echo.Context) error {
	// Retrieve all blocks from the blockchain
	blocks, err := s.bc.GetAllBlocks()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, echo.Map{"error": err.Error()})
	}

	// Convert each block to the Block struct for JSON response
	var jsonBlocks []Block
	for _, block := range blocks {
		jsonBlocks = append(jsonBlocks, intoJSONBlock(block))
	}

	// Return the JSON response
	return c.JSON(http.StatusOK, jsonBlocks)
}
func (s *Server) handleCreateAndSendNFT(c echo.Context) error {
	var req TransactionMessageRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: "Invalid request payload: " + err.Error()})
	}
	fromPrivKeyStr := s.privKey.PublicKey()
	toPrivKeyStr := s.privKey.PublicKey()
	err := sendTransactionNFT(fromPrivKeyStr, toPrivKeyStr, []byte(req.Message), req.Id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, APIError{Error: "Failed to send transaction: " + err.Error()})
	}
	return c.JSON(http.StatusOK, Message{"Send NFT successfully"})
}
func (s *Server) handleCreateAndSendTx(c echo.Context) error {
	var req TransactionRequest

	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: "Invalid request payload: " + err.Error()})
	}
	fromPrivKeyStr := s.privKey.PublicKey()
	toPrivKeyStr := s.privKey.PublicKey()
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, APIError{Error: "Failed to encode request: " + err.Error()})
	}

	err = sendTransaction(fromPrivKeyStr, toPrivKeyStr, reqBytes, req.Id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, APIError{Error: "Failed to send transaction: " + err.Error()})
	}
	return c.JSON(http.StatusOK, Message{"Send tx successfully"})
}

func (s *Server) handleGeneratePrivateKey(c echo.Context) error {
	response := PrivateKeyResponse{
		Publickey: s.privKey.PublicKey().String(),
	}
	return c.JSON(http.StatusOK, response)
}

func (s *Server) handlePostTx(c echo.Context) error {
	tx := core.NewTransaction(nil)
	if err := gob.NewDecoder(c.Request().Body).Decode(tx); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: "Failed to decode GOB data: " + err.Error()})
	}
	_, err := s.signTransaction(tx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, APIError{Error: "Failed to sign transaction: " + err.Error()})
	}
	s.txChan <- tx

	return c.NoContent(http.StatusOK)
}

func (s *Server) signTransaction(tx *core.Transaction) (*core.Transaction, error) {
	hash := tx.Hash(core.TxHasher{}).ToSlice()
	sig, err := s.privKey.Sign(hash)
	if err != nil {
		return nil, err
	}
	tx.Signature = &crypto.Signature{
		R: sig.R,
		S: sig.S,
	}
	return tx, nil

}

func (s *Server) handleGetAllTxs(c echo.Context) error {
	txs, err := s.bc.GetAllTransactions()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, txs)
}
func (s *Server) handleGetTransactionsWithTxInner(c echo.Context) error {
	txs, err := s.bc.GetTransactionsWithTxInner()
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, txs)
}

func (s *Server) handleGetTransactionsWithoutTxInner(c echo.Context) error {
	txs, err := s.bc.GetTransactionsWithoutTxInner()
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, txs)
}
func (s *Server) handleGetTx(c echo.Context) error {
	hash := c.Param("hash")

	b, err := hex.DecodeString(hash)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	tx, err := s.bc.GetTxByHash(types.HashFromBytes(b))
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, tx)
}

func (s *Server) handleGetBlock(c echo.Context) error {
	hashOrID := c.Param("hashorid")

	height, err := strconv.Atoi(hashOrID)
	// If the error is nil we can assume the height of the block is given.
	if err == nil {
		block, err := s.bc.GetBlock(uint32(height))
		if err != nil {
			return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
		}

		return c.JSON(http.StatusOK, intoJSONBlock(block))
	}

	// otherwise assume its the hash
	b, err := hex.DecodeString(hashOrID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	block, err := s.bc.GetBlockByHash(types.HashFromBytes(b))
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	return c.JSON(http.StatusOK, intoJSONBlock(block))
}

func intoJSONBlock(block *core.Block) Block {
	txResponse := TxResponse{
		TxCount: uint(len(block.Transactions)),
		Hashes:  make([]string, len(block.Transactions)),
	}

	for i := 0; i < int(txResponse.TxCount); i++ {
		txResponse.Hashes[i] = block.Transactions[i].Hash(core.TxHasher{}).String()
	}

	return Block{
		Hash:          block.Hash(core.BlockHasher{}).String(),
		Version:       block.Header.Version,
		Height:        block.Header.Height,
		DataHash:      block.Header.DataHash.String(),
		PrevBlockHash: block.Header.PrevBlockHash.String(),
		Timestamp:     block.Header.Timestamp,
		Validator:     block.Validator.Address().String(),
		Signature:     block.Signature.String(),
		TxResponse:    txResponse,
	}
}
func sendTransaction(fromPubKey crypto.PublicKey, toPubKey crypto.PublicKey, data []byte, value uint64) error {
	tx := core.NewTransaction(nil)
	tx.From = fromPubKey
	tx.To = toPubKey
	tx.Data = data
	tx.Value = value

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
func sendTransactionNFT(fromPubKey crypto.PublicKey, toPubKey crypto.PublicKey, data []byte, value uint64) error {
	tx := core.NewTransaction(nil)
	tx.From = fromPubKey
	tx.TxInner = core.CollectionTx{
		Id:       int64(value),
		MetaData: data,
	}

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
func (s *Server) handleGetBlockForTx(c echo.Context) error {
	txHash := c.Param("txhash")

	b, err := hex.DecodeString(txHash)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	txHashObj := types.HashFromBytes(b)
	block, err := s.bc.GetBlockByTxHash(txHashObj)
	if err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}

	if block == nil {
		return c.JSON(http.StatusNotFound, APIError{Error: "Block not found for transaction"})
	}

	return c.JSON(http.StatusOK, intoJSONBlock(block))
}
