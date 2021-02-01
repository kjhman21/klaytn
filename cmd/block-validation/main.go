// Copyright 2021 The klaytn Authors
// This file is part of the klaytn library.
//
// The klaytn library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The klaytn library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the klaytn library. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"encoding/json"
	"fmt"
	"github.com/klaytn/klaytn/blockchain/types"
	"github.com/klaytn/klaytn/cmd/utils"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/consensus/istanbul"
	istanbulCore "github.com/klaytn/klaytn/consensus/istanbul/core"
	"github.com/klaytn/klaytn/crypto/sha3"
	"github.com/klaytn/klaytn/log"
	"github.com/klaytn/klaytn/rlp"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"os"
)

var (
	Black   = Color("\033[1;30m%s\033[0m")
	Red     = Color("\033[1;31m%s\033[0m")
	Green   = Color("\033[1;32m%s\033[0m")
	Yellow  = Color("\033[1;33m%s\033[0m")
	Purple  = Color("\033[1;34m%s\033[0m")
	Magenta = Color("\033[1;35m%s\033[0m")
	Teal    = Color("\033[1;36m%s\033[0m")
	White   = Color("\033[1;37m%s\033[0m")
)

func Color(colorString string) func(...interface{}) string {
	sprint := func(args ...interface{}) string {
		return fmt.Sprintf(colorString,
			fmt.Sprint(args...))
	}
	return sprint
}

const (
	commandHelperTemplate = `{{.Name}}{{if .Subcommands}} command{{end}}{{if .Flags}} [command options]{{end}} [arguments...]
{{if .Description}}{{.Description}}
{{end}}{{if .Subcommands}}
SUBCOMMANDS:
	{{range .Subcommands}}{{.Name}}{{with .ShortName}}, {{.}}{{end}}{{ "\t" }}{{.Usage}}
	{{end}}{{end}}{{if .Flags}}
OPTIONS:
{{range $.Flags}}{{"\t"}}{{.}}
{{end}}
{{end}}`
)

var (
	// Git SHA1 commit hash of the release (set via linker flags)
	gitCommit = ""

	app *cli.App
)

func init() {
	app = utils.NewApp(gitCommit, "klaytn block validation tool")
	app.Action = utils.MigrateFlags(blockValidation)
	cli.CommandHelpTemplate = commandHelperTemplate
}

func sigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	// Clean seal is required for calculating proposer seal.
	rlp.Encode(hasher, types.IstanbulFilteredHeader(header, false))
	hasher.Sum(hash[:0])
	return hash
}

// ecrecover extracts the Klaytn account address from a signed header.
func ecrecover(header *types.Header) (common.Address, error) {
	// Retrieve the signature from the header extra-data
	istanbulExtra, err := types.ExtractIstanbulExtra(header)
	if err != nil {
		return common.Address{}, err
	}

	addr, err := istanbul.GetSignatureAddress(sigHash(header).Bytes(), istanbulExtra.Seal)
	if err != nil {
		return addr, err
	}
	return addr, nil
}

func blockValidation(c *cli.Context) error {
	var header types.Header
	var allFields map[string]interface{}

	jsonRaw, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(jsonRaw, &header)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(jsonRaw, &allFields)
	if err != nil {
		panic(err)
	}

	fmt.Println("original hash", allFields["hash"])
	recalculatedHash := header.Hash()
	if allFields["hash"] == recalculatedHash.String() {
		fmt.Println("\033[1;32mSAME\033[0m Recalculated hash is the same as original hash:", recalculatedHash.String())
	} else {
		fmt.Println("\033[1;31mDIFFERENT\033[0m Recalculated hash differs from original hash:", recalculatedHash.String())
	}

	extra, err := types.ExtractIstanbulExtra(&header)
	if err != nil {
		panic(err)
	}

	proposerAddr, err := ecrecover(&header)
	proposerIdx := -1
	proposerIdxFromIstanbulExtra := -1
	if err != nil {
		panic(err)
	}

	jsonCouncil, err := json.Marshal(allFields["council"])
	if err != nil {
		panic(err)
	}
	fmt.Println(len(allFields["council"].([]interface{})), "council:", string(jsonCouncil))
	councilAddrs := make([]common.Address, len(allFields["council"].([]interface{})))
	for i, v := range allFields["council"].([]interface{}) {
		councilAddrs[i] = common.HexToAddress(v.(string))
		if councilAddrs[i] == proposerAddr {
			proposerIdx = i
		}
	}

	addresses := make([]string, len(extra.Validators))
	for i, v := range extra.Validators {
		addresses[i] = v.String()
		if v == proposerAddr {
			proposerIdxFromIstanbulExtra = i
		}
	}
	jsonAddresses, err := json.Marshal(addresses)
	if err != nil {
		panic(err)
	}

	fmt.Println("Round", header.Round())
	fmt.Println(len(extra.Validators), "validator addresses:", string(jsonAddresses))

	committees := make([]string, len(extra.CommittedSeal))
	committeeIdx := make([]int, len(extra.CommittedSeal))
	committeeIdxFromIstanbulExtra := make([]int, len(extra.CommittedSeal))
	proposalSeal := istanbulCore.PrepareCommittedSeal(header.Hash())
	for i, seal := range extra.CommittedSeal {
		addr, err := istanbul.GetSignatureAddress(proposalSeal, seal)
		if err != nil {
			panic(err)
		}
		committees[i] = addr.String()
		committeeIdx[i] = -1
		committeeIdxFromIstanbulExtra[i] = -1
		for j, val := range councilAddrs {
			if val == addr {
				committeeIdx[i] = j
			}
		}
		for j, val := range extra.Validators {
			if val == addr {
				committeeIdxFromIstanbulExtra[i] = j
			}
		}
	}

	fmt.Println("proposer address:", proposerAddr.String(), "idx from council:", proposerIdx, "idx from istanbulExtra", proposerIdxFromIstanbulExtra)

	committeeAddrString, err := json.Marshal(committees)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(extra.CommittedSeal), "committee addresses:", string(committeeAddrString))

	committeeIdxString, err := json.Marshal(committeeIdx)
	if err != nil {
		panic(err)
	}
	fmt.Println("committee indices from council:", string(committeeIdxString))

	committeeIdxFromIstanbulExtraString, err := json.Marshal(committeeIdxFromIstanbulExtra)
	if err != nil {
		panic(err)
	}
	fmt.Println("committee indices from istanbulExtra:", string(committeeIdxFromIstanbulExtraString))

	return nil
}

func main() {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
