// Proof of Concept VSC Smart Contract in Golang
//
// Build command: tinygo build -o main.wasm -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown main.go
// Inspect Output: wasmer inspect main.wasm
// Run command (only works w/o SDK imports): wasmedge run main.wasm entrypoint 0
//
// Caveats:
// - Go routines, channels, and defer are disabled
// - panic() always halts the program, since you can't recover in a deferred function call
// - must import sdk or build fails
// - to mark a function as a valid entrypoint, it must be manually exported (//go:wasmexport <entrypoint-name>)
//
// TODO:
// - when panic()ing, call `env.abort()` instead of executing the unreachable WASM instruction
// - Remove _initalize() export & double check not necessary

package main

import (
	_ "contract-template/sdk" // ensure sdk is imported
	"os"

	"contract-template/sdk"

	"fmt"

	"crypto/sha256"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const SENDADDRESS = "tb1qd4erjn4tvt52c92yv66lwju9pzsd2ltph0xe5s"   // milo bitcoin qt
const CHANGEADDRESS = "tb1q5dgehs94wf5mgfasnfjsh4dqv6hz8e35w4w7tk" // milo bitcoin qt 2

func createScriptP2WSH(pubKeyHex string, tagHex string, network *chaincfg.Params) (string, []byte, error) {
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", nil, err
	}

	tagBytes, err := hex.DecodeString(tagHex)
	if err != nil {
		return "", nil, err
	}

	scriptBuilder := txscript.NewScriptBuilder()
	scriptBuilder.AddData(pubKeyBytes)              // Push pubkey
	scriptBuilder.AddOp(txscript.OP_CHECKSIGVERIFY) // OP_CHECKSIGVERIFY
	scriptBuilder.AddData(tagBytes)                 // Push tag/bits

	script, err := scriptBuilder.Script()
	if err != nil {
		return "", nil, err
	}

	witnessProgram := sha256.Sum256(script)
	address, err := btcutil.NewAddressWitnessScriptHash(witnessProgram[:], network)
	if err != nil {
		return "", nil, err
	}

	return address.EncodeAddress(), script, nil
}

type Utxo struct {
	TxId   string
	Vout   uint32
	Amount int64
}

func createSpendTransaction(
	utxo Utxo,
	redeemScript []byte,
	destAddress string,
	changeAddress string,
	sendAmount int64,
	feeAmount int64,
	network *chaincfg.Params,
) (*wire.MsgTx, []byte, error) {
	txHash, err := chainhash.NewHashFromStr(utxo.TxId)
	if err != nil {
		return nil, nil, err
	}

	tx := wire.NewMsgTx(wire.TxVersion)

	outPoint := wire.NewOutPoint(txHash, utxo.Vout)
	txIn := wire.NewTxIn(outPoint, nil, nil)
	tx.AddTxIn(txIn)

	destAddr, err := btcutil.DecodeAddress(destAddress, network)
	if err != nil {
		return nil, nil, err
	}

	// Create output script for destination
	destScript, err := txscript.PayToAddrScript(destAddr)
	if err != nil {
		return nil, nil, err
	}

	txOut := wire.NewTxOut(sendAmount, destScript)
	tx.AddTxOut(txOut)

	// change (return to address )
	changeAmount := utxo.Amount - sendAmount - feeAmount
	if changeAmount > 546 { // dust threshold
		change, err := btcutil.DecodeAddress(changeAddress, &chaincfg.MainNetParams)
		if err != nil {
			return nil, nil, err
		}
		changePkScript, err := txscript.PayToAddrScript(change)
		if err != nil {
			return nil, nil, err
		}
		txOutChange := wire.NewTxOut(changeAmount, changePkScript)
		tx.AddTxOut(txOutChange)
	}

	// Calculate witness sighash (the data to be signed)
	sigHashes := txscript.NewTxSigHashes(tx, txscript.NewCannedPrevOutputFetcher(
		redeemScript, utxo.Amount))

	witnessHash, err := txscript.CalcWitnessSigHash(
		redeemScript,
		sigHashes,
		txscript.SigHashAll,
		tx,
		0, // input index
		utxo.Amount,
	)
	if err != nil {
		return nil, nil, err
	}

	return tx, witnessHash, nil
}

type Signer interface {
	Sign(sigHash []byte) ([]byte, error)
}

type LocalSigner struct {
	private *btcec.PrivateKey
}

func NewLocalSigner(privateKeyHex string) (*LocalSigner, error) {
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, err
	}
	privateKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	return &LocalSigner{private: privateKey}, nil
}

func NewLocalSignerFromEnv() (*LocalSigner, error) {
	privKeyHex := os.Getenv("BTC_PRIVATE_KEY")
	if privKeyHex == "" {
		return nil, fmt.Errorf("BTC_PRIVATE_KEY not set")
	}
	return NewLocalSigner(privKeyHex)
}

func (s *LocalSigner) Sign(sigHash []byte) ([]byte, error) {
	signature := ecdsa.Sign(s.private, sigHash)
	return append(signature.Serialize(), byte(txscript.SigHashAll)), nil
}

func signAndFinalizeTransaction(
	tx *wire.MsgTx,
	sigHash []byte,
	signer Signer,
	redeemScript []byte,
) (string, error) {

	sigBytes, err := signer.Sign(sigHash)
	if err != nil {
		return "", err
	}

	tx.TxIn[0].Witness = wire.TxWitness{
		sigBytes,
		redeemScript,
	}

	// Serialize final transaction
	var serialized []byte
	err = tx.Serialize(&writeBuf{buf: &serialized})
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(serialized), nil
}

type writeBuf struct {
	buf *[]byte
}

func (w *writeBuf) Write(p []byte) (n int, err error) {
	*w.buf = append(*w.buf, p...)
	return len(p), nil
}

//go:wasmexport spend_btc
func SpendBTC(a *string) *string {
	sdk.Log(*a)

	network := &chaincfg.TestNet3Params

	// Example: Generate script address
	pubKey := "0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0"
	tag := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

	address, redeemScript, err := createScriptP2WSH(pubKey, tag, network)
	if err != nil {
		panic(err)
	}

	sdk.Log(fmt.Sprintf("Script Address: %s\n", address))
	// debugScript(redeemScript, tag)

	tx, sigHash, err := createSpendTransaction(
		Utxo{
			TxId:   "4604a462372fc7f838e8e746685b53bdae1222e44be4601456c7e2882074028c",
			Vout:   0,
			Amount: 121768, // amount (of utxo) in sats
		},
		redeemScript,
		SENDADDRESS,
		CHANGEADDRESS,
		7000, // amount to send
		2000, // fee in satoshis (amount send will be utxo amount - fee)
		network,
	)
	if err != nil {
		panic(err)
	}

	sdk.Log(fmt.Sprintf("\nSigHash to sign: %x\n", sigHash))

	signer, err := NewLocalSignerFromEnv()

	rawTx, err := signAndFinalizeTransaction(
		tx,
		sigHash,
		signer,
		redeemScript,
	)
	if err != nil {
		panic(err)
	}

	sdk.Log(fmt.Sprintf("Raw Transaction: %s\n", rawTx))
	// braodcast at: https://blockstream.info/testnet/tx/push

	return a
}
