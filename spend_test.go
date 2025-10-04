package spend_test

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/stretchr/testify/assert"
)

//go:embed artifacts/main.wasm
var ContractWasm []byte

func TestContract(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "spend_btc"
	ct.RegisterContract(contractId, ContractWasm)

	result, gasUsed, logs := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "sometxid",
			BlockId:              "block:spend_btc",
			Index:                69,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:someone"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "spend_btc",
		Payload:    json.RawMessage([]byte("1000")),
		RcLimit:    1000,
		Intents:    []contracts.Intent{},
	})
	fmt.Println("error:", *result.Err)
	assert.True(t, result.Success)                 // assert contract execution success
	assert.LessOrEqual(t, gasUsed, uint(10000000)) // assert this call uses no more than 10M WASM gas
	assert.GreaterOrEqual(t, len(logs), 1)         // assert at least 1 log emitted
	fmt.Println("Return value:", result.Ret)
}
