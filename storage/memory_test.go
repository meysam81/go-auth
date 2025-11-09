package storage

import (
	"context"
	"testing"
)

func TestUpdateUserEmailUniqueness(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	// Create first user
	user1 := &User{
		ID:       "user1",
		Email:    "user1@example.com",
		Username: "user1",
	}
	if err := store.CreateUser(ctx, user1); err != nil {
		t.Fatalf("Failed to create user1: %v", err)
	}

	// Create second user
	user2 := &User{
		ID:       "user2",
		Email:    "user2@example.com",
		Username: "user2",
	}
	if err := store.CreateUser(ctx, user2); err != nil {
		t.Fatalf("Failed to create user2: %v", err)
	}

	// Try to update user2's email to user1's email
	user2Updated := &User{
		ID:       "user2",
		Email:    "user1@example.com",
		Username: "user2",
	}
	err := store.UpdateUser(ctx, user2Updated)
	if err != ErrAlreadyExists {
		t.Errorf("Expected ErrAlreadyExists when updating to duplicate email, got: %v", err)
	}

	// Verify user2's email wasn't changed
	stored, err := store.GetUserByID(ctx, "user2")
	if err != nil {
		t.Fatalf("Failed to get user2: %v", err)
	}
	if stored.Email != "user2@example.com" {
		t.Errorf("User2's email was incorrectly changed to: %s", stored.Email)
	}

	// Verify user1 can still be found by their email
	user1Found, err := store.GetUserByEmail(ctx, "user1@example.com")
	if err != nil {
		t.Fatalf("Failed to get user1 by email: %v", err)
	}
	if user1Found.ID != "user1" {
		t.Errorf("Expected user1, got user: %s", user1Found.ID)
	}
}

func TestUpdateUserUsernameUniqueness(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	// Create first user
	user1 := &User{
		ID:       "user1",
		Email:    "user1@example.com",
		Username: "user1",
	}
	if err := store.CreateUser(ctx, user1); err != nil {
		t.Fatalf("Failed to create user1: %v", err)
	}

	// Create second user
	user2 := &User{
		ID:       "user2",
		Email:    "user2@example.com",
		Username: "user2",
	}
	if err := store.CreateUser(ctx, user2); err != nil {
		t.Fatalf("Failed to create user2: %v", err)
	}

	// Try to update user2's username to user1's username
	user2Updated := &User{
		ID:       "user2",
		Email:    "user2@example.com",
		Username: "user1",
	}
	err := store.UpdateUser(ctx, user2Updated)
	if err != ErrAlreadyExists {
		t.Errorf("Expected ErrAlreadyExists when updating to duplicate username, got: %v", err)
	}

	// Verify user2's username wasn't changed
	stored, err := store.GetUserByID(ctx, "user2")
	if err != nil {
		t.Fatalf("Failed to get user2: %v", err)
	}
	if stored.Username != "user2" {
		t.Errorf("User2's username was incorrectly changed to: %s", stored.Username)
	}

	// Verify user1 can still be found by their username
	user1Found, err := store.GetUserByUsername(ctx, "user1")
	if err != nil {
		t.Fatalf("Failed to get user1 by username: %v", err)
	}
	if user1Found.ID != "user1" {
		t.Errorf("Expected user1, got user: %s", user1Found.ID)
	}
}

func TestUpdateUserValidCases(t *testing.T) {
	store := NewInMemoryUserStore()
	ctx := context.Background()

	// Create user
	user := &User{
		ID:       "user1",
		Email:    "user1@example.com",
		Username: "user1",
	}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Valid update: changing to a new email
	userUpdated := &User{
		ID:       "user1",
		Email:    "newemail@example.com",
		Username: "user1",
	}
	if err := store.UpdateUser(ctx, userUpdated); err != nil {
		t.Errorf("Failed to update user with new email: %v", err)
	}

	// Verify the update
	stored, err := store.GetUserByEmail(ctx, "newemail@example.com")
	if err != nil {
		t.Fatalf("Failed to get user by new email: %v", err)
	}
	if stored.ID != "user1" {
		t.Errorf("Expected user1, got user: %s", stored.ID)
	}

	// Valid update: changing to a new username
	userUpdated2 := &User{
		ID:       "user1",
		Email:    "newemail@example.com",
		Username: "newusername",
	}
	if err := store.UpdateUser(ctx, userUpdated2); err != nil {
		t.Errorf("Failed to update user with new username: %v", err)
	}

	// Verify the update
	stored, err = store.GetUserByUsername(ctx, "newusername")
	if err != nil {
		t.Fatalf("Failed to get user by new username: %v", err)
	}
	if stored.ID != "user1" {
		t.Errorf("Expected user1, got user: %s", stored.ID)
	}

	// Valid update: updating same user with same email/username should work
	userUpdated3 := &User{
		ID:       "user1",
		Email:    "newemail@example.com",
		Username: "newusername",
	}
	if err := store.UpdateUser(ctx, userUpdated3); err != nil {
		t.Errorf("Failed to update user with same email/username: %v", err)
	}
}
