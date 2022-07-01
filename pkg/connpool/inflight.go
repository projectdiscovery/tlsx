package connpool

import (
	"net"
	"sync"
)

type InFlightConns struct {
	sync.RWMutex
	inflightConns map[net.Conn]struct{}
}

func NewInFlightConns() (*InFlightConns, error) {
	return &InFlightConns{inflightConns: make(map[net.Conn]struct{})}, nil
}

func (i *InFlightConns) Add(conn net.Conn) {
	i.Lock()
	defer i.Unlock()

	i.inflightConns[conn] = struct{}{}
}

func (i *InFlightConns) Remove(conn net.Conn) {
	i.Lock()
	defer i.Unlock()

	delete(i.inflightConns, conn)
}

func (i *InFlightConns) Close() {
	i.Lock()
	defer i.Unlock()

	for conn := range i.inflightConns {
		conn.Close()
		delete(i.inflightConns, conn)
	}
}
