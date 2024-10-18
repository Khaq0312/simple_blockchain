package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"time"
)

type Block struct {
	Timestamp     int64
	Transactions  []*Transaction
	PrevBlockHash []byte
	Hash          []byte
	//MerkleRoot    []byte
	nonce int
}

type Transaction struct {
	//Data []byte
	From      string
	To        string
	Amount    float64
	Signature []byte
}

type Blockchain struct {
	blocks             []*Block
	miningReward       int
	pendingTransaction []*Transaction
}

func (t *Transaction) calculateHash() []byte {
	data := t.From + t.To + strconv.FormatFloat(t.Amount, 'f', -1, 64)
	hash := sha256.Sum256([]byte(data))
	return hash[:]
}

func (t *Transaction) SignTransaction(privateKey *ecdsa.PrivateKey) error {
	pubKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)
	pubKeyHex := hex.EncodeToString(pubKeyBytes)

	if pubKeyHex != t.From {
		return fmt.Errorf("can not sign transactions for other wallet")
	}

	hashTx := t.calculateHash()
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashTx)
	if err != nil {
		return err
	}

	signature := append(r.Bytes(), s.Bytes()...)
	t.Signature = signature

	return nil
}
func (t *Transaction) isValid() bool {
	if t.From == "Reward of mining new block" {
		return true
	}

	if t.Signature == nil || len(t.Signature) == 0 {
		fmt.Println("no signature in this transaction")
		return false
	}

	hashTx := t.calculateHash()

	curve := elliptic.P256()
	pubKeyBytes, err := hex.DecodeString(t.From)
	if err != nil {
		fmt.Println("error decoding public key:", err)
		return false
	}

	x, y := elliptic.Unmarshal(curve, pubKeyBytes)
	if x == nil || y == nil {
		fmt.Println("error unmarshalling public key")
		return false
	}

	pubKey := ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	r := big.NewInt(0).SetBytes(t.Signature[:len(t.Signature)/2])
	s := big.NewInt(0).SetBytes(t.Signature[len(t.Signature)/2:])

	return ecdsa.Verify(&pubKey, hashTx, r, s)
}

func (b *Block) mineBlock(difficulty int) {
	target := bytes.Repeat([]byte{0}, difficulty/2)
	for {
		b.SetHash()
		if bytes.HasPrefix(b.Hash, target) {
			break
		}
		b.nonce++
	}
}

// get hash of the block
func (b *Block) SetHash() {
	timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))

	var transactionsData [][]byte
	for _, tx := range b.Transactions {
		txBytes, _ := json.Marshal(tx)
		transactionsData = append(transactionsData, txBytes)
	}

	headers := bytes.Join([][]byte{timestamp, b.PrevBlockHash, bytes.Join(transactionsData, []byte{}), []byte(strconv.Itoa(b.nonce))}, []byte{})
	hash := sha256.Sum256(headers)
	b.Hash = hash[:]

}

func (b *Block) hasValidTransaction() bool {
	for _, tx := range b.Transactions {
		if !tx.isValid() {
			return false
		}
	}
	return true
}
func (b *Block) PrintBlock() {
	t := time.Unix(b.Timestamp, 0)                        // Convert Unix timestamp to time.Time
	fmt.Printf("Timestamp: %s\n", t.Format(time.RFC3339)) // Format and print the time
	fmt.Printf("Prev hash: %x\n", b.PrevBlockHash)

	for i, tx := range b.Transactions {
		fmt.Printf("Transactions: %d     ", i)
		fmt.Printf("{ From: %s, To: %s, Amount: %.2f }\n", tx.From, tx.To, tx.Amount)
	}
	//fmt.Printf("Merkle Root: %x\n", b.MerkleRoot)

	fmt.Printf("Hash: %x\n", b.Hash)
	fmt.Printf("Nonce: %d\n", b.nonce)
}

func NewGenesisBlock() *Block {
	genesis := &Transaction{From: "", To: "", Amount: 0}
	b := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  []*Transaction{genesis},
		PrevBlockHash: []byte(""),
	}
	b.SetHash()
	return b
}

func (bc *Blockchain) GetLastBlock() *Block {
	prevBlock := bc.blocks[len(bc.blocks)-1]
	return prevBlock
}

func (bc *Blockchain) AddBlock(transaction []*Transaction) {
	prevBlock := bc.GetLastBlock()
	newBlock := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  transaction,
		PrevBlockHash: prevBlock.Hash,
	}

	//newBlock.MerkleRoot = newBlock.calculateMerkleRoot()

	startTime := time.Now() // Start timing the mining process

	newBlock.mineBlock(6)
	endTime := time.Now() // End timing the mining process
	duration := endTime.Sub(startTime)

	fmt.Printf("Time taken to mine block %d: %s\n", len(bc.blocks), duration) // Print the mining duration
	bc.blocks = append(bc.blocks, newBlock)

}

// mine a new block with a pending tracsaction, miner will receive transaction fee + 6.25BTC
// in reality, block size can not increase 1 MB, so miner can only choose transction that they want to include and which they dont
func (bc *Blockchain) MinePendingTransaction(mineRewardAddress string) {
	transactions := make([]*Transaction, len(bc.pendingTransaction))
	prevBlock := bc.GetLastBlock()

	copy(transactions, bc.pendingTransaction)

	transactions = append(transactions, &Transaction{
		From:   "Reward of mining new block",
		To:     mineRewardAddress,
		Amount: float64(bc.miningReward),
	})

	newBlock := &Block{
		Timestamp:     time.Now().Unix(),
		Transactions:  transactions,
		PrevBlockHash: prevBlock.Hash,
	}

	newBlock.mineBlock(4)
	bc.blocks = append(bc.blocks, newBlock)

	bc.pendingTransaction = []*Transaction{}
}

func (bc *Blockchain) CreateTransaction(t *Transaction) {
	bc.pendingTransaction = append(bc.pendingTransaction, t)
}

func (bc *Blockchain) AddTransaction(t *Transaction) {
	flag := true
	if t.From == "" || t.To == "" {
		fmt.Println("Transaction must include from address and to address")
		flag = false
	}

	if !t.isValid() {
		fmt.Println("Cannot add invalid transaction to chain")
		flag = false

	}
	if flag == true {
		bc.pendingTransaction = append(bc.pendingTransaction, t)
	}
}

func (bc *Blockchain) getBalanceOfAddress(address string) float64 {
	var balance float64 = 0
	for _, i := range bc.blocks {
		for _, j := range i.Transactions {
			if j.From == address {
				balance -= (j.Amount)
			}

			if j.To == address {
				balance += (j.Amount)
			}
		}
	}
	return balance
}

func NewBlockChain(miningReward int) *Blockchain {
	genesisBlock := NewGenesisBlock()
	return &Blockchain{
		blocks:             []*Block{genesisBlock},
		miningReward:       miningReward,
		pendingTransaction: []*Transaction{}}
}

func (bc *Blockchain) IsValid() bool {
	for i := 1; i < len(bc.blocks); i++ {
		currentBlock := bc.blocks[i]
		prevBlock := bc.blocks[i-1]

		if !currentBlock.hasValidTransaction() {
			return false
		}
		if !bytes.Equal(currentBlock.PrevBlockHash, prevBlock.Hash) {
			return false
		}

		currentBlock.SetHash()
		if !bytes.Equal(currentBlock.Hash, currentBlock.Hash) {
			return false
		}

		// if !bytes.Equal(currentBlock.calculateMerkleRoot(), currentBlock.MerkleRoot) {
		// 	return false
		// }
	}
	return true
}

// func (bc *Blockchain) VerifyTransaction(blockIndex, transactionIndex int) {
// 	block := bc.blocks[blockIndex]
// 	chosenTransaction := block.Transactions[transactionIndex]
// 	fmt.Printf("\nVerifying transaction: %s, %s, %2f\n", string(chosenTransaction.From), string(chosenTransaction.To), chosenTransaction.Amount)

//	if block.VerifyBlockTransactions() {
//		fmt.Println("Transactions in block", blockIndex, "are valid.")
//	} else {
//
//		fmt.Println("Transactions in block", blockIndex, "are NOT valid.")
//	}
func main() {
	bc := NewBlockChain(100)

	// Specify private keys for different users
	privKey1Hex := "cdfc73a7e702ec5c1f0df2161e52b98ba8f104d44e968ed92ef7792b2e864faf"
	privKey2Hex := "e4f28c8d4f607c3f6b893bf4e6c8cc4e222b3ef5086d3d27a42de2b1b91e2d99"

	// Decode hexadecimal private keys
	privKeyBytes1, err := hex.DecodeString(privKey1Hex)
	if err != nil {
		fmt.Println("Error decoding private key 1:", err)
		return
	}
	privKeyBytes2, err := hex.DecodeString(privKey2Hex)
	if err != nil {
		fmt.Println("Error decoding private key 2:", err)
		return
	}

	curve := elliptic.P256()

	// Create private keys from decoded bytes
	privKey1 := new(ecdsa.PrivateKey)
	privKey1.PublicKey.Curve = curve
	privKey1.D = new(big.Int).SetBytes(privKeyBytes1)
	privKey1.PublicKey.X, privKey1.PublicKey.Y = curve.ScalarBaseMult(privKey1.D.Bytes())

	privKey2 := new(ecdsa.PrivateKey)
	privKey2.PublicKey.Curve = curve
	privKey2.D = new(big.Int).SetBytes(privKeyBytes2)
	privKey2.PublicKey.X, privKey2.PublicKey.Y = curve.ScalarBaseMult(privKey2.D.Bytes())

	// Derive the public keys
	pubKeyBytes1 := elliptic.Marshal(curve, privKey1.PublicKey.X, privKey1.PublicKey.Y)
	pubKeyHex1 := hex.EncodeToString(pubKeyBytes1)

	pubKeyBytes2 := elliptic.Marshal(curve, privKey2.PublicKey.X, privKey2.PublicKey.Y)
	pubKeyHex2 := hex.EncodeToString(pubKeyBytes2)

	// Create transactions involving different users
	transaction1 := &Transaction{From: pubKeyHex1, To: pubKeyHex2, Amount: 100}
	transaction2 := &Transaction{From: pubKeyHex2, To: pubKeyHex1, Amount: 30}

	// Sign and add transactions to the blockchain
	err = transaction1.SignTransaction(privKey1)
	if err != nil {
		fmt.Println("Error signing transaction 1:", err)
		return
	}
	bc.AddTransaction(transaction1)

	err = transaction2.SignTransaction(privKey2)
	if err != nil {
		fmt.Println("Error signing transaction 2:", err)
		return
	}
	bc.AddTransaction(transaction2)

	// Mine pending transactions
	bc.MinePendingTransaction(pubKeyHex1)

	// Check balance for each user
	address1 := pubKeyHex1
	balance1 := bc.getBalanceOfAddress(address1)
	fmt.Printf("\nBalance of address 1: %.2f\n", balance1)

	transaction3 := &Transaction{From: pubKeyHex1, To: pubKeyHex2, Amount: 15}

	// Sign and add transactions to the blockchain
	err = transaction3.SignTransaction(privKey1)
	if err != nil {
		fmt.Println("Error signing transaction 3:", err)
		return
	}
	bc.AddTransaction(transaction3)
	bc.MinePendingTransaction(pubKeyHex1)
	balance1 = bc.getBalanceOfAddress(address1)

	fmt.Printf("\nBalance of address 1: %.2f\n", balance1)
}
