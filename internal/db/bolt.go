package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	bolt "go.etcd.io/bbolt"
)

type BoltDB struct {
	db *bolt.DB
}

var (
	ordersBucketName       = []byte("acme_orders")
	accountsBucketName     = []byte("acme_accounts")
	accountEabsBucketName  = []byte("acme_account_eabs")
	accountKeysBucketName  = []byte("acme_account_keys")
	authzsBucketName       = []byte("acme_authzs")
	certificatesBucketName = []byte("acme_certificates")
)

var ErrNotFound = errors.New("not found")

func IsErrNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func (b BoltDB) Seed() error {
	bucketsToCreate := [][]byte{accountEabsBucketName, ordersBucketName, accountsBucketName, accountKeysBucketName, authzsBucketName, certificatesBucketName}

	return b.db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range bucketsToCreate {
			_, err := tx.CreateBucket(bucket)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (b BoltDB) SaveAccountKey(accountID []byte, key *jose.JSONWebKey) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		v, err := key.MarshalJSON()
		if err != nil {
			return err
		}

		bucket, err := boltGetBucket(tx, accountKeysBucketName)
		if err != nil {
			return err
		}

		return bucket.Put(accountID, v)
	})
}

func (b BoltDB) GetAccountKey(accountID []byte) (*jose.JSONWebKey, error) {
	k := &jose.JSONWebKey{}
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket, err := boltGetBucket(tx, accountKeysBucketName)
		if err != nil {
			return err
		}

		v := bucket.Get(accountID)
		if v == nil {
			return ErrNotFound
		}

		return k.UnmarshalJSON(v)
	})
	if err != nil {
		return nil, err
	}
	return k, nil
}

func boltGetBucket(tx *bolt.Tx, bucketName []byte) (*bolt.Bucket, error) {
	bucket := tx.Bucket(bucketName)
	if bucket != nil {
		return bucket, nil
	}

	bucket, err := tx.CreateBucket(bucketName)
	if err != nil {
		return nil, fmt.Errorf("failed to make bucket %s: %v", bucketName, err)
	}
	return bucket, nil
}

func boltUpdator[DbT any](db *bolt.DB, bucketName []byte, key []byte, updateCallback func(*DbT) error) (*DbT, error) {
	var obj DbT

	err := db.Update(func(tx *bolt.Tx) error {
		bucket, err := boltGetBucket(tx, bucketName)
		if err != nil {
			return err
		}

		v := bucket.Get(key)
		if v == nil {
			return ErrNotFound
		}

		err = json.Unmarshal(v, &obj)
		if err != nil {
			return err
		}

		err = updateCallback(&obj)
		if err != nil {
			return err
		}

		newV, err := json.Marshal(obj)
		if err != nil {
			return err
		}

		return bucket.Put(key, newV)
	})
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

func boltGetter[DbT any](db *bolt.DB, bucketName []byte, key []byte) (*DbT, error) {
	var obj DbT

	err := db.View(func(tx *bolt.Tx) error {
		bucket, err := boltGetBucket(tx, bucketName)
		if err != nil {
			return err
		}

		v := bucket.Get(key)
		if v == nil {
			return ErrNotFound
		}

		return json.Unmarshal(v, &obj)
	})

	if err != nil {
		return nil, err
	}

	return &obj, nil
}

func boltSaver[DbT any](db *bolt.DB, bucketName []byte, key []byte, obj *DbT) error {
	return db.Update(func(tx *bolt.Tx) error {
		return boltSaverTx(tx, bucketName, key, obj)
	})
}

func boltSaverTx[DbT any](tx *bolt.Tx, bucketName []byte, key []byte, obj *DbT) error {
	bucket, err := boltGetBucket(tx, bucketName)
	if err != nil {
		return err
	}

	v, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	return bucket.Put(key, v)
}

func (b BoltDB) GetAccount(accountID []byte) (*DBAccount, error) {
	return boltGetter[DBAccount](b.db, accountsBucketName, accountID)
}
func (b BoltDB) CreateAccount(account DBAccount, jwk *jose.JSONWebKey) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		err := boltSaver[DBAccount](b.db, accountsBucketName, []byte(account.ID), &account)
		if err != nil {
			return err
		}

		v, err := jwk.MarshalJSON()
		if err != nil {
			return err
		}

		bucket, err := boltGetBucket(tx, accountKeysBucketName)
		if err != nil {
			return err
		}

		return bucket.Put([]byte(account.ID), v)
	})
}
func (b BoltDB) UpdateAccount(accountID []byte, updateCallback func(*DBAccount) error) (*DBAccount, error) {
	return boltUpdator[DBAccount](b.db, accountsBucketName, accountID, updateCallback)
}
func (b BoltDB) DeleteAccount(accountID []byte) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bucket, err := boltGetBucket(tx, accountsBucketName)
		if err != nil {
			return err
		}
		return bucket.Delete(accountID)
	})
}

func (b BoltDB) GetOrder(orderID []byte) (*DBOrder, error) {
	return boltGetter[DBOrder](b.db, ordersBucketName, orderID)
}
func (b BoltDB) CreateOrder(order DBOrder) error {
	return boltSaver[DBOrder](b.db, ordersBucketName, []byte(order.ID), &order)
}
func (b BoltDB) UpdateOrder(orderID []byte, updateCallback func(*DBOrder) error) (*DBOrder, error) {
	return boltUpdator[DBOrder](b.db, ordersBucketName, orderID, updateCallback)
}

func (b *BoltDB) CreateCertificate(cert DBCertificate) error {
	return boltSaver[DBCertificate](b.db, certificatesBucketName, []byte(cert.ID), &cert)
}
func (b *BoltDB) GetCertificate(certID []byte) (*DBCertificate, error) {
	return boltGetter[DBCertificate](b.db, certificatesBucketName, certID)
}

func (b *BoltDB) CreateAuthz(authz DBAuthz) error {
	return boltSaver[DBAuthz](b.db, authzsBucketName, []byte(authz.ID), &authz)
}
func (b *BoltDB) GetAuthz(authzID []byte) (*DBAuthz, error) {
	return boltGetter[DBAuthz](b.db, authzsBucketName, authzID)
}

// IsAuthzLocked implements DB.
func (b *BoltDB) IsAuthzLocked(authzID []byte) (bool, error) {
	authz, err := boltGetter[DBAuthz](b.db, authzsBucketName, authzID)
	if err != nil {
		return false, err
	}
	return authz.Locked, nil
}

func (b *BoltDB) TryTakeAuthzLock(authzID []byte) (bool, error) {
	success := false
	err := b.db.Update(func(tx *bolt.Tx) error {
		bucket, err := boltGetBucket(tx, authzsBucketName)
		if err != nil {
			return err
		}

		v := bucket.Get(authzID)
		if v == nil {
			return ErrNotFound
		}

		var authz DBAuthz
		err = json.Unmarshal(v, &authz)
		if err != nil {
			return err
		}

		if authz.Locked {
			success = false
			return nil
		}
		authz.Locked = true
		newV, err := json.Marshal(authz)
		if err != nil {
			success = false
			return nil
		}

		err = bucket.Put(authzID, newV)
		if err != nil {
			success = false
			return nil
		}

		success = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return success, nil
}

func (b *BoltDB) UnlockAuthz(authzID []byte) error {
	_, err := boltUpdator[DBAuthz](b.db, authzsBucketName, authzID, func(authz *DBAuthz) error {
		authz.Locked = false
		return nil
	})
	return err
}
func (b *BoltDB) UpdateAuthz(authzID []byte, updateCallback func(authzToUpdate *DBAuthz) error) (*DBAuthz, error) {
	return boltUpdator[DBAuthz](b.db, authzsBucketName, authzID, updateCallback)
}

func NewBoltDb(path string) (DB, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	return &BoltDB{
		db: db,
	}, nil
}
