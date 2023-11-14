def get_new_analytics_logging_obj():
	from azure.storage.blob import BlobAnalyticsLogging, RetentionPolicy
	return BlobAnalyticsLogging(
		version="1.0",
		delete= True,
		read= True,
		write= True,
		retention_policy=RetentionPolicy(
			enabled=True,
			days=1
		),
	)
