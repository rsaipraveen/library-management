package initializers

import models "library-management/Models"

func SyncDatabase() {
	DB.AutoMigrate(&models.UserProfile{})
}
