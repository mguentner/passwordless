package state

import badger "github.com/dgraph-io/badger/v3"

func (s *State) AllKeys() ([][]byte, error) {
	keys := [][]byte{}
	err := s.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			keys = append(keys, k)
		}
		return nil
	})
	return keys, err
}
