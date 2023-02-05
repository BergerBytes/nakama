// Copyright 2021 The Nakama Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"github.com/gofrs/uuid"
)

type SessionCache interface {
	Stop()

	// IsValidSession Check if a given user, expiry, and session token combination is valid.
	IsValidSession(userID uuid.UUID, exp int64, token string) bool
	// IsValidRefresh Check if a given user, expiry, and refresh token combination is valid.
	IsValidRefresh(userID uuid.UUID, exp int64, token string) bool
	// Add a valid session and/or refresh token for a given user.
	Add(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string)
	// Remove a session and/or refresh token for a given user.
	Remove(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string)
	// RemoveAll of a user's session and refresh tokens.
	RemoveAll(userID uuid.UUID)
	// Ban Mark a set of users as banned.
	Ban(userIDs []uuid.UUID)
	// Unban a set of users.
	Unban(userIDs []uuid.UUID)
}
