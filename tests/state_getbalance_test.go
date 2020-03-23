package tests

import (
	"bufio"
	"fmt"
	"github.com/klaytn/klaytn/blockchain/state"
	"github.com/klaytn/klaytn/common"
	"github.com/klaytn/klaytn/params"
	"github.com/klaytn/klaytn/storage/database"
	"github.com/stretchr/testify/require"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
)

func toKlay(balance *big.Int) string {
	return new(big.Int).Div(balance, big.NewInt(params.KLAY)).String() + "." +
		new(big.Int).Rem(balance, big.NewInt(params.KLAY)).String()
}

func TestBalanceSanityCheck(t *testing.T) {
	dir := "./klay/chaindata"
	if os.Getenv("DATADIR") != "" {
		dir = os.Getenv("DATADIR")
	}
	dbc := &database.DBConfig{Dir: dir, Partitioned: true, NumStateTriePartitions: 4, DBType: database.LevelDB, LevelDBCacheSize: 16, OpenFilesLimit: 16}
	dbm := database.NewDBManager(dbc)

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

	d := state.NewDatabase(dbm)
	st, err := state.New(b.Root(), d)
	require.NoError(t, err)

	fmt.Println("blocknumber = ", b.NumberU64())

	f, err := os.Open("addrList.csv")
	require.NoError(t, err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		v := strings.Split(l, ",")
		address := common.HexToAddress(v[0])
		balance := v[2]

		stateBalance := toKlay(st.GetBalance(address))

		if stateBalance != balance {
			fmt.Printf("balance of %s = %s, (MUST BE %s)\n", address.Hex(), balance, stateBalance)
		}
	}
	require.NoError(t, scanner.Err())

}
