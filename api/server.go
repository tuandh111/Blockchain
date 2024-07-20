package api

import (
	"Blockchain/crypto"
	"encoding/gob"
	"encoding/hex"
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
	PrivateKey string `json:"privateKey"`
}
type Server struct {
	txChan chan *core.Transaction
	ServerConfig
	bc      *core.Blockchain
	privKey *crypto.PrivateKey
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
	return e.Start(s.ListenAddr)
}
func (s *Server) handleGeneratePrivateKey(c echo.Context) error {
	privKey := crypto.GeneratePrivateKey()

	response := PrivateKeyResponse{
		PrivateKey: privKey.PublicKey().String(),
	}

	return c.JSON(http.StatusOK, response)
}

func (s *Server) handlePostTx(c echo.Context) error {
	tx := &core.Transaction{}

	if err := gob.NewDecoder(c.Request().Body).Decode(tx); err != nil {
		return c.JSON(http.StatusBadRequest, APIError{Error: err.Error()})
	}
	signedTx, err := s.signTransaction(tx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, APIError{Error: err.Error()})
	}

	s.txChan <- signedTx
	//s.txChan <- tx

	return nil
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
