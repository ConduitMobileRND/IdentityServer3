INSERT INTO [dbo].[AspNetUserLogins] (UserId, LoginProvider, ProviderKey) 
SELECT UserId,Provider,provideruserid FROM [dbo].[webpages_OAuthMembership]
