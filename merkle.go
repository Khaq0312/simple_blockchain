package main

import (
	//"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type Node struct {
	Left  *Node
	Right *Node
	Hash  []byte
}

type Tree struct {
	Root *Node
}

func NewMerkleTree(data [][]byte) *Tree {
	var nodes []Node
	//hash leaf node
	for _, tx := range data {
		hash := sha256.Sum256(tx)
		nodes = append(nodes, Node{Hash: hash[:]})
	}

	for len(nodes) > 1 {
		var newLevel []Node
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			var right Node
			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {
				right = nodes[i]
			}

			combinedHash := append(left.Hash, right.Hash...)
			newHash := sha256.Sum256((combinedHash))

			newLevel = append(newLevel, Node{
				Left:  &left,
				Right: &right,
				Hash:  newHash[:],
			})
		}
		nodes = newLevel

	}
	return &Tree{Root: &nodes[0]}

}

func (b *Block) calculateMerkleRoot() []byte {
	var data [][]byte

	// Convert transactions to byte slices
	for _, tx := range b.Transactions {
		txBytes, _ := json.Marshal(tx)
		data = append(data, txBytes)
	}

	// Create Merkle tree and get the root
	tree := NewMerkleTree(data)
	return tree.Root.Hash
}

func (mt *Tree) PrintTree() {
	printNode(mt.Root, 0)
}

func printNode(node *Node, level int) {

	if node == nil {
		return
	}

	// Print the hash of the current node at the given level
	fmt.Printf("Level %d: %s\n", level, hex.EncodeToString(node.Hash))

	// Recursively print the left and right child nodes
	printNode(node.Left, level+1)
	printNode(node.Right, level+1)
}

// func (b *Block) VerifyBlockTransactions() bool {
// 	// Calculate the Merkle root of the current transactions
// 	calculatedMerkleRoot := b.calculateMerkleRoot()

// 	// Compare with the stored MerkleRoot
// 	return bytes.Equal(calculatedMerkleRoot, b.MerkleRoot)
// }
