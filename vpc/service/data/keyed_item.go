package data

type KeyedItem interface {
	Key() string
	String() string
}

type NilItem struct {
}

func (n *NilItem) Key() string {
	return "nilitem"
}

func (n *NilItem) String() string {
	return "Nilitem{}"
}
