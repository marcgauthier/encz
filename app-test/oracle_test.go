package main

import (
	"testing"
	"time"
)

func TestOracleJoinOrderingAndCascade(t *testing.T) {
	o := newOracle()
	now := time.Unix(1_700_000_000, 0)
	o.add("tenants", makeRecord("tenants", 1, 0, 1, now))
	o.add("tenants", makeRecord("tenants", 2, 0, 1, now))

	userA := makeRecord("users", 1, 1, 1, now)
	userA.Amount = 10
	userB := makeRecord("users", 2, 2, 1, now)
	userB.Amount = 20
	o.add("users", userA)
	o.add("users", userB)
	o.add("profiles", makeRecord("profiles", 1, 2, 1, now))

	joined, err := o.joinRows("users", false, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(joined) != 2 || joined[0].Child.ID != 2 || joined[0].Parent.ID != 2 {
		t.Fatalf("unexpected join: %+v", joined)
	}

	o.deleteCascade("tenants", 2)
	if _, ok := o.get("users", 2); ok {
		t.Fatal("child user survived parent cascade")
	}
	if _, ok := o.get("profiles", 1); ok {
		t.Fatal("grandchild profile survived parent cascade")
	}
	if _, ok := o.get("users", 1); !ok {
		t.Fatal("unrelated row was deleted")
	}
}

func TestRecordComparisonIncludesEveryField(t *testing.T) {
	base := makeRecord("orders", 1, 7, 3, time.Unix(1_700_000_000, 0))
	if err := compareRecord(base, base); err != nil {
		t.Fatal(err)
	}
	mutated := base
	mutated.Payload = append([]byte(nil), base.Payload...)
	mutated.Payload[0] ^= 1
	if err := compareRecord(base, mutated); err == nil {
		t.Fatal("payload mismatch was not detected")
	}
}
