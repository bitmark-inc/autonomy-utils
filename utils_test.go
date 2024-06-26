package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBlockchainByAddress(t *testing.T) {
	assert.Equal(t, GetBlockchainByAddress("0x8F6ccB4cF3C3bed6830CB6E2824C18AdCFA8eBBd"), EthereumBlockchain)
	assert.Equal(t, GetBlockchainByAddress("tz1MTXXDg7uudxmEieyf2rmZyLBST7ykndWw"), TezosBlockchain)
	assert.Equal(t, GetBlockchainByAddress("aWDT2s4Lba3rrBtqLghY61PLr2gLZuvSy9uvXRmwLmhAixXuNa"), BitmarkBlockchain)
}

func TestVerifyETHSignature(t *testing.T) {
	timestamp := "1635846129"
	signature := "0x3929aafc8d6149672418df04f8e44d902f54c9e534c4b5a5a0fd3dd9a521f20c72f269f9ed00350490132dd1bac1e40b3c4f039c18fd25ab36b07db2aa48b6ff1b"
	address := "0x1C67a342d2aCc6b6Eb25166af4Bc27c5e8C419AE"
	result, err := VerifyETHSignature(timestamp, signature, address)
	assert.NoError(t, err)
	assert.True(t, result)
}

func TestVerifyTezosSignature(t *testing.T) {
	timestamp := "1670487641"
	signature := "edsigtnqtat3zpoRDFs4ndjKJtSLFYRYYs6dNgFP7zHNBkFiBK6tpDhkaV5cNk3enB2SnPRKaArzr9uYzLk4jTqUke6jB3bTzhn"
	address := "tz1TuTEBP14iDRUuxtkxRJbqBU8LcawZinEk"
	publicKey := "edpku9caPvH6WM63iUt5FAWUwX9GPaRRJ68APVjwGXsxLbVHbRq3m7"
	result, err := VerifyTezosSignature(timestamp, signature, address, publicKey)
	assert.NoError(t, err)
	assert.True(t, result)
}
