package verify

import (
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/internal/roles"
)

type Role struct {
	KeyIDs    map[string]struct{}
	Threshold int
}

func (r *Role) ValidKey(id string) bool {
	_, ok := r.KeyIDs[id]
	return ok
}

type DB struct {
	roles map[string]*Role
	keys  map[string]*data.Key
}

func NewDB() *DB {
	return &DB{
		roles: make(map[string]*Role),
		keys:  make(map[string]*data.Key),
	}
}

// NewDBFromDelegations returns a DB that verifies delegations
// of a given Targets.
func NewDBFromDelegations(d *data.Delegations) (*DB, error) {
	db := &DB{
		roles: make(map[string]*Role, len(d.Roles)),
		keys:  make(map[string]*data.Key, len(d.Keys)),
	}
	for _, r := range d.Roles {
		if _, ok := roles.TopLevelRoles[r.Name]; ok {
			return nil, ErrInvalidDelegatedRole
		}
		role := &data.Role{Threshold: r.Threshold, KeyIDs: r.KeyIDs}
		if err := db.AddRole(r.Name, role); err != nil {
			return nil, err
		}
	}
	for id, k := range d.Keys {
		if err := db.AddKey(id, k); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func (db *DB) AddKey(id string, k *data.Key) error {
	v, ok := Verifiers[k.Type]
	if !ok {
		return nil
	}
	if !k.ContainsID(id) {
		return ErrWrongID{}
	}
	if !v.ValidKey(k.Value.Public) {
		return ErrInvalidKey
	}

	db.keys[id] = k

	return nil
}

func (db *DB) AddRole(name string, r *data.Role) error {
	if r.Threshold < 1 {
		return ErrInvalidThreshold
	}

	role := &Role{
		KeyIDs:    make(map[string]struct{}),
		Threshold: r.Threshold,
	}
	for _, id := range r.KeyIDs {
		if len(id) != data.KeyIDLength {
			return ErrInvalidKeyID
		}
		role.KeyIDs[id] = struct{}{}
	}

	db.roles[name] = role
	return nil
}

func (db *DB) GetKey(id string) *data.Key {
	return db.keys[id]
}

func (db *DB) GetRole(name string) *Role {
	return db.roles[name]
}
