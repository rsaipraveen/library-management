package initializers

import "library-management/internals/models"

func SyncDatabase() {
	DB.AutoMigrate(&models.UserProfile{})
	DB.AutoMigrate(&models.BookModels{})
}
