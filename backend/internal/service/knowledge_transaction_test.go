package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"vulnark/internal/model"
	"vulnark/internal/repository"
)

func newKnowledgeTransactionService(db *gorm.DB) KnowledgeService {
	return NewKnowledgeService(db, repository.NewKnowledgeRepository(db), repository.NewTagRepository(db), repository.NewUserRepository(db))
}

func createTransactionKnowledge(t *testing.T, svc KnowledgeService, tags []string) *model.KnowledgeBase {
	t.Helper()
	knowledge, err := svc.CreateKnowledge(&model.KnowledgeCreateRequest{Title: "Original", Content: "Body", Category: "security", Type: "article", Tags: tags, Metadata: model.KBMetadata{"test": true}}, 1)
	require.NoError(t, err)
	return knowledge
}

func TestKnowledgeEmptyMetadataRoundTrip(t *testing.T) {
	db := newBusinessTestDB(t)
	svc := newKnowledgeTransactionService(db)
	knowledge, err := svc.CreateKnowledge(&model.KnowledgeCreateRequest{Title: "No metadata", Content: "Body", Category: "security", Type: "article", Tags: []string{"empty"}}, 1)
	require.NoError(t, err)
	stored, err := svc.GetKnowledgeByID(knowledge.ID)
	require.NoError(t, err)
	require.NotNil(t, stored.Metadata)
	require.Empty(t, stored.Metadata)
	require.NoError(t, svc.UpdateKnowledge(knowledge.ID, &model.KnowledgeUpdateRequest{Title: "Edited", Tags: []string{}}))
	stored, err = svc.GetKnowledgeByID(knowledge.ID)
	require.NoError(t, err)
	require.Equal(t, "Edited", stored.Title)
	require.Empty(t, stored.Tags)
	require.Empty(t, stored.Metadata)
}

func assertKnowledgeTags(t *testing.T, db *gorm.DB, id uint, text string, counts map[string]int) {
	t.Helper()
	var knowledge model.KnowledgeBase
	require.NoError(t, db.First(&knowledge, id).Error)
	require.Equal(t, text, knowledge.Tags)
	var tags []model.Tag
	require.NoError(t, db.Find(&tags).Error)
	actual := make(map[string]int)
	for _, tag := range tags {
		actual[tag.Name] = tag.UsageCount
	}
	require.Equal(t, counts, actual)
	linked, err := repository.NewKnowledgeRepository(db).GetKnowledgeTags(id)
	require.NoError(t, err)
	var names []string
	for _, tag := range linked {
		names = append(names, tag.Name)
	}
	if text == "" {
		require.Empty(t, names)
	} else {
		require.ElementsMatch(t, normalizeKnowledgeTags([]string{text}), names)
	}
}

func TestKnowledgeTagsTrimDeduplicateAndDeltaCounts(t *testing.T) {
	db := newBusinessTestDB(t)
	svc := newKnowledgeTransactionService(db)
	knowledge := createTransactionKnowledge(t, svc, []string{" alpha ", "alpha", "", " beta "})
	assertKnowledgeTags(t, db, knowledge.ID, "alpha,beta", map[string]int{"alpha": 1, "beta": 1})
	require.EqualValues(t, 2, businessRowCount(t, db, &model.KnowledgeTag{}))

	// An omitted slice leaves both representations and counts unchanged.
	require.NoError(t, svc.UpdateKnowledge(knowledge.ID, &model.KnowledgeUpdateRequest{Title: "Edited"}))
	assertKnowledgeTags(t, db, knowledge.ID, "alpha,beta", map[string]int{"alpha": 1, "beta": 1})
	require.NoError(t, svc.UpdateKnowledge(knowledge.ID, &model.KnowledgeUpdateRequest{Tags: []string{"beta", "beta", " gamma "}}))
	assertKnowledgeTags(t, db, knowledge.ID, "beta,gamma", map[string]int{"alpha": 0, "beta": 1, "gamma": 1})
	require.NoError(t, svc.UpdateKnowledge(knowledge.ID, &model.KnowledgeUpdateRequest{Tags: []string{"beta", "gamma"}}))
	assertKnowledgeTags(t, db, knowledge.ID, "beta,gamma", map[string]int{"alpha": 0, "beta": 1, "gamma": 1})
	other := createTransactionKnowledge(t, svc, []string{"beta"})
	assertKnowledgeTags(t, db, knowledge.ID, "beta,gamma", map[string]int{"alpha": 0, "beta": 2, "gamma": 1})
	require.NoError(t, svc.UpdateKnowledge(knowledge.ID, &model.KnowledgeUpdateRequest{Tags: []string{}}))
	assertKnowledgeTags(t, db, knowledge.ID, "", map[string]int{"alpha": 0, "beta": 1, "gamma": 0})
	require.NoError(t, svc.DeleteKnowledge(other.ID))
	assertKnowledgeTags(t, db, knowledge.ID, "", map[string]int{"alpha": 0, "beta": 0, "gamma": 0})
	require.Zero(t, businessRowCount(t, db, &model.KnowledgeTag{}))
}

func TestKnowledgeCreateTransactionRollback(t *testing.T) {
	for _, table := range []string{"tags", "knowledge_tags"} {
		t.Run(table, func(t *testing.T) {
			db := newBusinessTestDB(t)
			failBusinessCreate(t, db, table)
			_, err := newKnowledgeTransactionService(db).CreateKnowledge(&model.KnowledgeCreateRequest{Title: "Rollback", Content: "Body", Category: "security", Type: "article", Tags: []string{"new"}, Metadata: model.KBMetadata{"test": true}}, 1)
			require.ErrorContains(t, err, "injected")
			require.Zero(t, businessRowCount(t, db, &model.KnowledgeBase{}))
			require.Zero(t, businessRowCount(t, db, &model.Tag{}))
			require.Zero(t, businessRowCount(t, db, &model.KnowledgeTag{}))
		})
	}
}

func TestKnowledgeUpdateTransactionRollback(t *testing.T) {
	for _, phase := range []string{"association", "count"} {
		t.Run(phase, func(t *testing.T) {
			db := newBusinessTestDB(t)
			svc := newKnowledgeTransactionService(db)
			knowledge := createTransactionKnowledge(t, svc, []string{"old"})
			if phase == "association" {
				failBusinessCreate(t, db, "knowledge_tags")
			} else {
				require.NoError(t, db.Callback().Update().Before("gorm:update").Register("test:count-error", func(tx *gorm.DB) {
					if tx.Statement.Table == "tags" {
						tx.AddError(errors.New("injected count failure"))
					}
				}))
				t.Cleanup(func() { require.NoError(t, db.Callback().Update().Remove("test:count-error")) })
			}
			err := svc.UpdateKnowledge(knowledge.ID, &model.KnowledgeUpdateRequest{Title: "Must roll back", Tags: []string{"replacement"}})
			require.ErrorContains(t, err, "injected")
			assertKnowledgeTags(t, db, knowledge.ID, "old", map[string]int{"old": 1})
			var stored model.KnowledgeBase
			require.NoError(t, db.First(&stored, knowledge.ID).Error)
			require.Equal(t, "Original", stored.Title)
		})
	}
}

func TestKnowledgeDeleteTransactionRollback(t *testing.T) {
	db := newBusinessTestDB(t)
	svc := newKnowledgeTransactionService(db)
	knowledge := createTransactionKnowledge(t, svc, []string{"delete"})
	require.NoError(t, db.Callback().Delete().Before("gorm:delete").Register("test:knowledge-delete", func(tx *gorm.DB) {
		if tx.Statement.Table == "knowledge_bases" {
			tx.AddError(errors.New("injected delete failure"))
		}
	}))
	t.Cleanup(func() { require.NoError(t, db.Callback().Delete().Remove("test:knowledge-delete")) })
	require.ErrorContains(t, svc.DeleteKnowledge(knowledge.ID), "injected delete failure")
	assertKnowledgeTags(t, db, knowledge.ID, "delete", map[string]int{"delete": 1})
}

func TestKnowledgeTagLookupErrorDoesNotCreateTag(t *testing.T) {
	db := newBusinessTestDB(t)
	failLookup := true
	require.NoError(t, db.Callback().Query().Before("gorm:query").Register("test:tag-query", func(tx *gorm.DB) {
		if failLookup && tx.Statement.Table == "tags" {
			tx.AddError(errors.New("tag lookup failed"))
		}
	}))
	t.Cleanup(func() { require.NoError(t, db.Callback().Query().Remove("test:tag-query")) })
	_, err := newKnowledgeTransactionService(db).CreateKnowledge(&model.KnowledgeCreateRequest{Title: "Rollback", Content: "Body", Category: "security", Type: "article", Tags: []string{"lookup"}, Metadata: model.KBMetadata{"test": true}}, 1)
	require.ErrorContains(t, err, "tag lookup failed")
	failLookup = false
	require.Zero(t, businessRowCount(t, db, &model.KnowledgeBase{}))
	require.Zero(t, businessRowCount(t, db, &model.Tag{}))
}

func TestKnowledgeTagUniquePair(t *testing.T) {
	db := newBusinessTestDB(t)
	knowledge := createTransactionKnowledge(t, newKnowledgeTransactionService(db), []string{"unique"})
	var link model.KnowledgeTag
	require.NoError(t, db.Where("knowledge_id = ?", knowledge.ID).First(&link).Error)
	require.Error(t, db.Create(&model.KnowledgeTag{KnowledgeID: link.KnowledgeID, TagID: link.TagID}).Error)
}
