// Copyright 2018 The klaytn Authors
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

package statedb

import (
	"encoding/json"
	"fmt"
	"github.com/klaytn/klaytn/blockchain/types/account"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/crypto/sha3"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/klaytn/ser/rlp"
	"github.com/klaytn/klaytn/storage/database"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"math/big"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"testing"
)

////////////////////////////////////////////////////////////////////////////////
// Additional member functions of Iterator (defined in iterator.go)
////////////////////////////////////////////////////////////////////////////////
func (it *Iterator) NextAny() bool {
	if it.nodeIt.Next(true) {
		return true
	}
	it.Err = it.nodeIt.Error()
	return false
}

////////////////////////////////////////////////////////////////////////////////
// Additional member functions of nodeIterator (defined in iterator.go)
////////////////////////////////////////////////////////////////////////////////
func (it *nodeIterator) GetType() string {
	if len(it.stack) == 0 {
		return ""
	}
	return reflect.TypeOf(it.stack[len(it.stack)-1].node).String()
}

func (it *nodeIterator) GetKeyNibbles() (key, key_nibbles string) {
	k := it.path
	k = k[:len(k)-(len(k)&1)]

	for i, n := range it.path {
		if i == len(it.path)-1 && n == 16 {
			key_nibbles += "T"
		} else {
			key_nibbles += indices[n]
		}
	}

	return string(hexToKeybytes(k)), key_nibbles
}

////////////////////////////////////////////////////////////////////////////////
// NodeIntMap
//
// Stores a mapping between node* and int
// This is required to make an integer ID of a node object for id in vis.js.
////////////////////////////////////////////////////////////////////////////////
type NodeIntMap struct {
	hashMap map[*node]int
	counter int
}

func NewHashIntMap() *NodeIntMap {
	return &NodeIntMap{
		hashMap: map[*node]int{},
		counter: 1,
	}
}

func (m *NodeIntMap) Get(h *node) int {
	if _, ok := m.hashMap[h]; !ok {
		m.hashMap[h] = m.counter
		m.counter++
	}

	return m.hashMap[h]
}

////////////////////////////////////////////////////////////////////////////////
// VisNode
//
// Describes a node object in vis.js.
////////////////////////////////////////////////////////////////////////////////
type VisNode struct {
	Id          int             `json:"id"`
	Label       string          `json:"label"`
	Level       int             `json:"level"`
	Addr        string          `json:"addr"`
	Str         string          `json:"str"`
	Typename    string          `json:"typename"`
	AccountAddr string          `json:"accountAddr"`
	AccountType string          `json:"accountType"`
	Obj         account.Account `json:"obj"`
	AddrSha3    string          `json:"addrSha3"`
}

func (v *VisNode) String() string {
	b, _ := json.Marshal(*v)
	return string(b)
}

func SerializeNodes(nodes []VisNode) (ret string) {
	for _, n := range nodes {
		ret += fmt.Sprintf("%s, \n", n.String())
	}

	return
}

////////////////////////////////////////////////////////////////////////////////
// VisEdge
//
// Describes an edge object in vis.js.
////////////////////////////////////////////////////////////////////////////////
type VisEdge struct {
	from  int
	to    int
	label string
}

func (e *VisEdge) String() string {
	return fmt.Sprintf("{from:%d, to:%d, label:'%s'}", e.from, e.to, e.label)
}

func SerializeEdges(edges []VisEdge) (ret string) {
	for _, e := range edges {
		ret += fmt.Sprintf("%s, \n", e.String())
	}

	return
}

type AccountInfo struct {
	Addr    string
	Type    string
	Balance string
}

func (a *AccountInfo) String() string {
	return fmt.Sprintf("%s,%s,%s", a.Addr, a.Type, a.Balance)
}

func SerializeAccountInfo(accs []AccountInfo) (ret string) {
	for _, a := range accs {
		ret += fmt.Sprintf("%s\n", a.String())
	}

	return ret
}

////////////////////////////////////////////////////////////////////////////////
// TestPrintTrie
//
// You can execute only this test by `go test -run TestPrintTrie`
////////////////////////////////////////////////////////////////////////////////
func TestPrintTrie(t *testing.T) {
	trie := newEmptyTrie()
	vals := []struct{ k, v string }{

		//{"klaytn", "wookiedoo"},
		//{"horse", "stallion"},
		//{"shaman", "horse"},
		//{"doge", "coin"},
		//{"dog", "puppy"},
		{"do", "verb"},
		{"dok", "puppyuyyy"},
		{"somethingveryoddindeedthis is", "myothernodedata"},
		{"barb", "ba"},
		{"bard", "bc"},
		{"bars", "bb"},
		{"bar", "b"},
		{"fab", "z"},
		{"food", "ab"},
		{"foos", "aa"},
		{"foo", "a"},
		{"aardvark", "c"},
		//{"bar", "b"},
		//{"barb", "bd"},
		//{"bars", "be"},
		//{"fab", "z"},
		//{"foo", "a"},
		//{"foos", "aa"},
		//{"food", "ab"},
		{"jars", "d"},
	}
	all := make(map[string]string)
	for _, val := range vals {
		all[val.k] = val.v
		trie.Update([]byte(val.k), []byte(val.v))
	}
	trie.Commit(nil)

	nodeIntMap := NewHashIntMap()
	var visNodes []VisNode
	var visEdges []VisEdge

	it := NewIterator(trie.NodeIterator(nil))
	for it.NextAny() {
		nodeIt, _ := it.nodeIt.(*nodeIterator)

		key, key_nibbles := nodeIt.GetKeyNibbles()

		edgeLabel := ""

		myId := nodeIntMap.Get(&nodeIt.stack[len(nodeIt.stack)-1].node)
		pId := 0
		if len(nodeIt.stack) > 1 {
			parent := &nodeIt.stack[len(nodeIt.stack)-2].node
			pId = nodeIntMap.Get(parent)
			switch (*parent).(type) {
			case *fullNode:
				edgeLabel = key_nibbles[len(key_nibbles)-1:]
			default:
			}
		}

		label := string("ROOT")
		if len(key_nibbles) > 0 {
			label = fmt.Sprintf("%s\\n%s", key, key_nibbles)
			if key_nibbles[len(key_nibbles)-1:] == "T" {
				label += fmt.Sprintf("\\nValue:%s", string(nodeIt.LeafBlob()))
			}
		}

		visNodes = append(visNodes, VisNode{
			Id:       myId,
			Addr:     fmt.Sprintf("%p", &nodeIt.stack[len(nodeIt.stack)-1].node),
			Str:      nodeIt.stack[len(nodeIt.stack)-1].node.fstring("0"),
			Label:    label,
			Level:    len(nodeIt.stack),
			Typename: nodeIt.GetType(),
		})

		if pId > 0 {
			visEdges = append(visEdges, VisEdge{
				from:  pId,
				to:    myId,
				label: edgeLabel,
			})
		}
	}

	fmt.Printf("var nodes = new vis.DataSet([%s]);\n", SerializeNodes(visNodes))
	fmt.Printf("var edges = new vis.DataSet([%s]);\n", SerializeEdges(visEdges))
}

func getGenesisAddrs() ([]common.Address, error) {
	jsonFile, err := os.Open("genesis.json")
	if err != nil {
		return nil, err
	}
	byteValue, _ := ioutil.ReadAll(jsonFile)

	var result map[string]interface{}
	json.Unmarshal([]byte(byteValue), &result)

	addrs := make([]common.Address, 0, len(result["alloc"].(map[string]interface{})))

	for k := range result["alloc"].(map[string]interface{}) {
		addrs = append(addrs, common.HexToAddress(string(k)))
	}

	return addrs, nil
}

func hashKey(addr common.Address) (h common.Hash) {
	hasher := sha3.NewKeccak256()

	hasher.Write(addr[:])
	hasher.Sum(h[:0])

	return h
}

func toKlay(balance *big.Int) string {
	return new(big.Int).Div(balance, big.NewInt(params.KLAY)).String() + "." +
		new(big.Int).Rem(balance, big.NewInt(params.KLAY)).String()
}

func TestDumpStateTrie(t *testing.T) {
	dir := "./klay/chaindata"
	if os.Getenv("DATADIR") != "" {
		dir = os.Getenv("DATADIR")
	}
	dbc := &database.DBConfig{Dir: dir, Partitioned: true, NumStateTriePartitions: 4, DBType: database.LevelDB, LevelDBCacheSize: 16, OpenFilesLimit: 16}
	dbm := database.NewDBManager(dbc)
	db := NewDatabaseWithCache(dbm, 1024, 0)

	dump := false
	if os.Getenv("DUMP") != "" {
		dump = true
	}

	headerHash := dbm.ReadHeadHeaderHash()
	b := dbm.ReadBlockByHash(headerHash)
	if b == nil {
		b = dbm.ReadBlockByNumber(0)
	}

	if os.Getenv("BLOCKNUM") != "" {
		blknum, err := strconv.ParseInt(os.Getenv("BLOCKNUM"), 10, 0)
		if err != nil {
			panic(err)
		}
		b = dbm.ReadBlockByNumber(uint64(blknum))
	}

	if b == nil {
		panic("block is nil!!")
	}

	fmt.Println("block number = ", b.NumberU64())

	nodesjs, err := os.Create("nodes.js")
	require.NoError(t, err)

	edgesjs, err := os.Create("edges.js")
	require.NoError(t, err)

	addrListf, err := os.Create("addrList.csv")
	require.NoError(t, err)

	zeroUsersf, err := os.Create("zeroUser.csv")
	require.NoError(t, err)

	addrs, err := getGenesisAddrs()
	require.NoError(t, err)

	keyAddrMap := make(map[common.Hash]common.Address)

	trie, err := NewTrie(b.Root(), db)
	require.NoError(t, err)

	for _, a := range addrs {
		keyAddrMap[hashKey(a)] = a
	}

	nodeIntMap := NewHashIntMap()
	var visNodes []VisNode
	var visEdges []VisEdge
	var accs []AccountInfo
	var zeroUsers []AccountInfo

	re := regexp.MustCompile(`\r?\n`)

	if dump == false {
		_, err := nodesjs.WriteString("var nodes = new vis.DataSet([")
		require.NoError(t, err)
		_, err = edgesjs.WriteString("var edges = new vis.DataSet([")
		require.NoError(t, err)
	}

	numAccounts := 0
	userAccounts := 0
	nonZeroBalanceUserAccounts := 0
	contractAccounts := 0
	zeroUserAccounts := 0

	it := NewIterator(trie.NodeIterator(nil))
	for it.NextAny() {
		nodeIt, _ := it.nodeIt.(*nodeIterator)

		key, key_nibbles := nodeIt.GetKeyNibbles()

		edgeLabel := ""

		myId := nodeIntMap.Get(&nodeIt.stack[len(nodeIt.stack)-1].node)
		pId := 0
		if len(nodeIt.stack) > 1 {
			parent := &nodeIt.stack[len(nodeIt.stack)-2].node
			pId = nodeIntMap.Get(parent)
			switch (*parent).(type) {
			case *fullNode:
				edgeLabel = key_nibbles[len(key_nibbles)-1:]
			default:
			}
		}

		label := string("ROOT")
		var accountAddr common.Address
		accountType := "ROOT"
		addrSha3 := ""
		var obj account.Account
		if len(key_nibbles) > 0 {
			addrSha3 = fmt.Sprintf("%s", common.Bytes2Hex([]byte(key)))
			label = addrSha3
			accountAddr = common.Address{}
			accountType = "NODE"
			if key_nibbles[len(key_nibbles)-1:] == "T" {
				var ok bool
				if accountAddr, ok = keyAddrMap[common.BytesToHash([]byte(key))]; !ok {
					accountAddr = common.BytesToAddress(dbm.ReadPreimage(common.BytesToHash([]byte(key))))
				}
				ser := account.NewAccountSerializer()
				b := nodeIt.LeafBlob()
				err := rlp.DecodeBytes(b, &ser)
				require.NoError(t, err)
				j, err := json.MarshalIndent(ser, "  ", "  ")
				str := string(j)
				str = re.ReplaceAllString(str, "\\n")
				require.NoError(t, err)
				label += fmt.Sprintf("\nBalance:%s", ser.GetAccount().GetBalance().String())
				obj = ser.GetAccount()
				accountType = obj.Type().String()

				ai := AccountInfo{
					Addr:    accountAddr.Hex(),
					Type:    accountType,
					Balance: toKlay(obj.GetBalance()),
				}
				numAccounts++
				if ai.Type == account.ExternallyOwnedAccountType.String() {
					userAccounts++
					if ai.Balance == "0.0" {
						zeroUserAccounts++
					} else {
						nonZeroBalanceUserAccounts++
					}
				} else {
					contractAccounts++
				}
				if dump {
					accs = append(accs, ai)
					if ai.Type == account.ExternallyOwnedAccountType.String() && ai.Balance == "0.0" {
						zeroUsers = append(zeroUsers, ai)
					}
				} else {
					_, err := addrListf.WriteString(ai.String() + "\n")
					require.NoError(t, err)
					if ai.Type == account.ExternallyOwnedAccountType.String() && ai.Balance == "0.0" {
						_, err = zeroUsersf.WriteString(ai.String() + "\n")
						require.NoError(t, err)
					}
				}
			}
		}

		vi := VisNode{
			Id:   myId,
			Addr: fmt.Sprintf("%p", &nodeIt.stack[len(nodeIt.stack)-1].node),
			Str:  nodeIt.stack[len(nodeIt.stack)-1].node.fstring("0"), AddrSha3: addrSha3,
			AccountAddr: accountAddr.Hex(),
			AccountType: accountType,
			Label:       label,
			Level:       len(nodeIt.stack),
			Typename:    nodeIt.GetType(),
			Obj:         obj,
		}
		if dump {
			visNodes = append(visNodes, vi)
		} else {
			_, err := nodesjs.WriteString(vi.String() + ", \n")
			require.NoError(t, err)
		}

		if pId > 0 {
			ve := VisEdge{
				from:  pId,
				to:    myId,
				label: edgeLabel,
			}
			if dump {
				visEdges = append(visEdges, ve)
			} else {
				_, err := edgesjs.WriteString(ve.String() + ", \n")
				require.NoError(t, err)
			}
		}
	}

	fmt.Println("num accounts = ", numAccounts)
	fmt.Println("userAccounts = ", userAccounts)
	fmt.Println("nonZeroBalanceUserAccounts = ", nonZeroBalanceUserAccounts)
	fmt.Println("contractAccounts = ", contractAccounts)
	fmt.Println("zeroUserAccounts = ", zeroUserAccounts)

	if dump {
		_, err = nodesjs.WriteString(fmt.Sprintf("var nodes = new vis.DataSet([%s]);\n", SerializeNodes(visNodes)))
		require.NoError(t, err)
		_, err = edgesjs.WriteString(fmt.Sprintf("var edges = new vis.DataSet([%s]);\n", SerializeEdges(visEdges)))
		require.NoError(t, err)

		_, err = addrListf.WriteString(SerializeAccountInfo(accs))
		require.NoError(t, err)

		_, err = zeroUsersf.WriteString(SerializeAccountInfo(zeroUsers))
		require.NoError(t, err)
	} else {
		_, err := nodesjs.WriteString("]);\n")
		require.NoError(t, err)
		_, err = edgesjs.WriteString("]);\n")
		require.NoError(t, err)
	}
}
