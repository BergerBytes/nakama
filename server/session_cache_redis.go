package server

import (
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
	"strings"
	"sync"
	"time"
)

type RedisSessionCache struct {
	sync.RWMutex

	ctx         context.Context
	ctxCancelFn context.CancelFunc
	logger      *zap.Logger

	client *redis.Client
}

type Key struct {
	UserID    string
	TokenKind string
	Scope     string
}

const (
	tokenKindSession = "token"
	tokenKindRefresh = "refresh"
)

func NewRedisSessionCache(address string, logger *zap.Logger) SessionCache {
	if address == "" {
		return nil
	}

	logger.Info("Initializing Redis session cache", zap.String("address", address))

	options, err := redis.ParseURL(address)
	if err != nil {
		return nil
	}

	options.DB = 0

	ctx, ctxCancelFn := context.WithCancel(context.Background())

	s := &RedisSessionCache{
		ctx:         ctx,
		ctxCancelFn: ctxCancelFn,
		logger:      logger,
		client:      redis.NewClient(options),
	}

	_, err = s.client.Ping(s.ctx).Result()
	if err != nil {
		ctxCancelFn()
		logger.Error("Could not initialize Redis session cache", zap.Error(err))
		return nil
	}

	logger.Info("Redis session cache initialized")

	return s
}

func (s *RedisSessionCache) Stop() {
	_ = s.client.Close()
	s.ctxCancelFn()
}

func (s *RedisSessionCache) IsValidSession(userID uuid.UUID, exp int64, token string) bool {
	s.RLock()
	defer s.RUnlock()

	if isBanned := s.isBanned(userID); isBanned {
		return false
	}

	key := fmt.Sprintf("%s:%s:%s", userID, tokenKindSession, s.getSessionScope(token))
	exists, _ := s.client.Exists(s.ctx, key).Result()

	return exists > 0
}

func (s *RedisSessionCache) IsValidRefresh(userID uuid.UUID, exp int64, token string) bool {
	s.RLock()
	defer s.RUnlock()

	if isBanned := s.isBanned(userID); isBanned {
		return false
	}

	key := fmt.Sprintf("%s:%s:%s", userID, tokenKindRefresh, s.getSessionScope(token))
	exists, _ := s.client.Exists(s.ctx, key).Result()

	return exists > 0
}

func (s *RedisSessionCache) Add(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	s.Lock()
	defer s.Unlock()

	if isBanned := s.isBanned(userID); isBanned {
		return
	}

	if sessionToken != "" {
		s.addToken(userID.String(), sessionToken, tokenKindSession, time.Duration(sessionExp)*time.Second)
	}

	if refreshToken != "" {
		s.addToken(userID.String(), refreshToken, tokenKindRefresh, time.Duration(refreshExp)*time.Second)
	}
}

func (s *RedisSessionCache) Remove(userID uuid.UUID, sessionExp int64, sessionToken string, refreshExp int64, refreshToken string) {
	s.Lock()
	defer s.Unlock()

	if sessionToken != "" {
		s.removeToken(userID.String(), sessionToken, tokenKindSession)
	}

	if refreshToken != "" {
		s.removeToken(userID.String(), refreshToken, tokenKindRefresh)
	}
}

func (s *RedisSessionCache) RemoveAll(userID uuid.UUID) {
	s.Lock()
	defer s.Unlock()

	userSessionKeys, err := s.getSessionKeys(userID.String())
	if err != nil {
		s.logger.Error("Error getting session keys", zap.Error(err))
		return
	}

	for _, key := range userSessionKeys {
		s.client.Del(s.ctx, key)
	}
}

func (s *RedisSessionCache) Ban(userIDs []uuid.UUID) {
	s.Lock()
	defer s.Unlock()
	for _, userID := range userIDs {
		s.client.Set(s.ctx, fmt.Sprintf("%s:%s", "BAN", userID), "true", 0)

		userSessionKeys, err := s.getSessionKeys(userID.String())
		if err != nil {
			s.logger.Error("Error getting session keys", zap.Error(err))
			continue
		}

		for _, key := range userSessionKeys {
			s.client.Del(s.ctx, key)
		}
	}
}

func (s *RedisSessionCache) Unban(userIDs []uuid.UUID) {
	s.Lock()
	defer s.Unlock()
	for _, userID := range userIDs {
		s.client.Del(s.ctx, fmt.Sprintf("%s:%s", "BAN", userID))
	}
}

func (s *RedisSessionCache) parseClaims(in string) (map[string]interface{}, error) {
	token, _ := jwt.Parse(in, nil)

	if token == nil {
		s.logger.Error("Could not parse token")
		return map[string]interface{}{}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		s.logger.Error("Could not parse claims")
		return map[string]interface{}{}, nil
	}

	return claims, nil
}

// GetSessionScope returns the session scope in the given token.
func (s *RedisSessionCache) getSessionScope(token string) string {
	claims, err := s.parseClaims(token)
	if err != nil {
		s.logger.Error("Error parsing session token claims", zap.Error(err), zap.Any("claims", claims))
		return "global"
	}

	claimVars, ok := claims["vrs"].(map[string]interface{})
	if !ok {
		s.logger.Error("Claim vars not found in token", zap.Any("claims", claims))
		return "global"
	}

	sessionScope, ok := claimVars["session_scope"].(string)
	if !ok {
		s.logger.Error("Session scope not found in token vars", zap.Any("claims", claims))
		return "global"
	}

	return sessionScope
}

// IsBanned returns true if the user is banned.
func (s *RedisSessionCache) isBanned(userID uuid.UUID) bool {
	key := fmt.Sprintf("%s:%s", "BAN", userID)
	exists, _ := s.client.Exists(s.ctx, key).Result()

	return exists > 0
}

// AddToken adds a token to the cache.
func (s *RedisSessionCache) addToken(userId string, token string, tokenKind string, expiration time.Duration) {
	sessionScope := s.getSessionScope(token)

	key := fmt.Sprintf("%s:%s:%s", userId, tokenKind, sessionScope)
	s.client.Set(s.ctx, key, token, expiration)
}

// RemoveToken removes a token from the cache.
func (s *RedisSessionCache) removeToken(userId string, token string, tokenKind string) {
	sessionScope := s.getSessionScope(token)

	key := fmt.Sprintf("%s:%s:%s", userId, tokenKind, sessionScope)
	s.client.Del(s.ctx, key)
}

// GetSessionKeys returns all session keys for a given user.
func (s *RedisSessionCache) getSessionKeys(userId string) ([]string, error) {
	var cursor uint64

	// pattern to match keys
	pattern := userId + ":*"

	// use redis.Scan to retrieve all keys that match the pattern
	var keys []string
	iter := s.client.Scan(s.ctx, cursor, pattern, 100).Iterator()
	for iter.Next(s.ctx) {
		keys = append(keys, iter.Val())
	}

	return keys, nil
}

func (s *RedisSessionCache) getSessionTokens(userId string) (map[Key]string, error) {
	var cursor uint64

	// pattern to match keys
	pattern := userId + ":*"

	// use redis.Scan to retrieve all keys that match the pattern
	var keys map[Key]string
	iter := s.client.Scan(s.ctx, cursor, pattern, 100).Iterator()
	for iter.Next(s.ctx) {
		keyString := iter.Val()
		parts := strings.Split(keyString, ":")

		key := Key{
			UserID:    parts[0],
			TokenKind: parts[1],
			Scope:     parts[2],
		}

		keys[key] = s.client.Get(s.ctx, keyString).Val()
	}

	return keys, nil
}
