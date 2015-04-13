IF OBJECT_ID('AspNetUserRoles', 'U') IS NOT NULL
BEGIN
DROP TABLE AspNetUserRoles;
END

IF OBJECT_ID('AspNetUserClaims', 'U') IS NOT NULL
BEGIN
DROP TABLE AspNetUserClaims;
END

IF OBJECT_ID('AspNetUserLogins', 'U') IS NOT NULL
BEGIN
DROP TABLE AspNetUserLogins;
END

IF OBJECT_ID('AspNetRoles', 'U') IS NOT NULL
BEGIN
DROP TABLE AspNetRoles;
END

IF OBJECT_ID('AspNetUsers', 'U') IS NOT NULL
BEGIN
DROP TABLE AspNetUsers;
END



CREATE TABLE [dbo].[AspNetUsers](
       [Id] [nvarchar](128) NOT NULL,
       [ApplicationId] [UNIQUEIDENTIFIER] NOT NULL,
       [MobileAlias] [nvarchar](max) NULL,
       [IsAnonymous] [bit] NOT NULL,
       [LastActivityDate] [DATETIME] DEFAULT GETDATE() NOT NULL,
       [MobilePIN] [nvarchar](max) NULL,
       [LoweredEmail] [nvarchar](max) NULL,
       [LoweredUserName] [nvarchar](max) NULL,
       [PasswordQuestion] [nvarchar](max) NULL,
       [PasswordAnswer] [nvarchar](max) NULL,
       [IsApproved] [bit] NOT NULL,
       [IsLockedOut] [bit] NOT NULL,
       [CreateDate] [datetime] NOT NULL,
       [LastLoginDate] [datetime] NOT NULL,
       [LastPasswordChangedDate] [DATETIME] DEFAULT GETDATE() NOT NULL,
       [LastLockoutDate] [datetime] NOT NULL,
       [FailedPasswordAttemptCount] [int] NOT NULL,
       [FailedPasswordAttemptWindowStart] [datetime] NOT NULL,
       [FailedPasswordAnswerAttemptCount] [int] NOT NULL,
       [FailedPasswordAnswerAttemptWindowStart] [datetime] NOT NULL,
       [Comment] [nvarchar](max) NULL,
       [Email] [nvarchar](256) NULL,
       [EmailConfirmed] [bit] NOT NULL,
       [PasswordHash] [nvarchar](max) NULL,
       [SecurityStamp] [nvarchar](max) NULL,
       [PhoneNumber] [nvarchar](max) NULL,
       [PhoneNumberConfirmed] [bit] NOT NULL,
       [TwoFactorEnabled] [bit] NOT NULL,
       [LockoutEndDateUtc] [datetime] NULL,
       [LockoutEnabled] [bit] NOT NULL,
       [AccessFailedCount] [int] NOT NULL,
       [UserName] [nvarchar](256) NOT NULL,
CONSTRAINT [PK_dbo.AspNetUsers] PRIMARY KEY CLUSTERED 
(
       [Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO



INSERT INTO AspNetUsers(Id,ApplicationId,UserName,PasswordHash,SecurityStamp,
LoweredUserName,IsAnonymous,LastActivityDate,
Email,PasswordAnswer,IsApproved,IsLockedOut,CreateDate,LastLoginDate,
LastLockoutDate,FailedPasswordAttemptCount,
FailedPasswordAnswerAttemptWindowStart,FailedPasswordAnswerAttemptCount,FailedPasswordAttemptWindowStart,
EmailConfirmed,PhoneNumberConfirmed,TwoFactorEnabled,LockoutEnabled,
AccessFailedCount)
SELECT dbo.UserProfiles.UserId,'8F0087DC-49FA-469B-923F-35AA897B46BD',UserProfiles.UserName,

CASE 
       WHEN webpages_Membership.PasswordFormat IS NULL 
              THEN webpages_Membership.PASSWORD
    ELSE (webpages_Membership.Password+'|'+CAST(webpages_Membership.PasswordFormat as varchar)+'|'+
webpages_Membership.PasswordSalt)
END

,NewID(),
UserProfiles.UserName,
0,COALESCE(UserProfiles.LastActivityDate,GETDATE()),UserProfiles.UserName,webpages_Membership.PasswordAnswer,

CASE 
	WHEN webpages_Membership.IsConfirmed IS NULL
		THEN 0
	ELSE
		webpages_Membership.IsConfirmed
end
,


COALESCE(webpages_Membership.IsLockedOut,0),


CASE 
	WHEN webpages_Membership.CreateDate IS NULL
		THEN GETDATE()
	ELSE webpages_Membership.CreateDate
END



,GETDATE(),
COALESCE(webpages_Membership.LastLockoutDate,GETDATE()),0, COALESCE(webpages_Membership.FailedPasswordAnswerAttemptWindowStart,GETDATE()),
COALESCE(webpages_Membership.FailedPasswordAnswerAttemptCount,0),COALESCE(webpages_Membership.FailedPasswordAttemptWindowStart,GETDATE()),1,0,0,0,0
FROM UserProfiles
LEFT OUTER JOIN webpages_Membership ON 
 UserProfiles.UserId = webpages_Membership.UserId 







CREATE TABLE [dbo].[AspNetRoles] (
    [Id]   NVARCHAR (128) NOT NULL,
    [Name] NVARCHAR (MAX) NOT NULL,
    PRIMARY KEY NONCLUSTERED ([Id] ASC),
);


INSERT INTO AspNetRoles(Id,Name)
SELECT RoleId,RoleName
FROM dbo.v2Roles;

CREATE TABLE [dbo].[AspNetUserRoles] (
    [UserId] NVARCHAR (128) NOT NULL,
    [RoleId] NVARCHAR (128) NOT NULL,
    CONSTRAINT [PK_dbo.AspNetUserRoles] PRIMARY KEY CLUSTERED ([UserId] ASC, [RoleId] ASC),
    CONSTRAINT [FK_dbo.AspNetUserRoles_dbo.AspNetRoles_RoleId] FOREIGN KEY ([RoleId]) REFERENCES [dbo].[AspNetRoles] ([Id]) ON DELETE CASCADE,
    CONSTRAINT [FK_dbo.AspNetUserRoles_dbo.AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [dbo].[AspNetUsers] ([Id]) ON DELETE CASCADE
);



--TODO:How roles from v2Roles related to users?
--INSERT INTO AspNetUserRoles(UserId,RoleId)
--SELECT UserId,RoleId
--FROM dbo.v2Roles;




CREATE TABLE [dbo].[AspNetUserClaims] (
    [Id]         INT            IDENTITY (1, 1) NOT NULL,
    [ClaimType]  NVARCHAR (MAX) NULL,
    [ClaimValue] NVARCHAR (MAX) NULL,
    [UserId]    NVARCHAR (128) NOT NULL,
    CONSTRAINT [PK_dbo.AspNetUserClaims] PRIMARY KEY CLUSTERED ([Id] ASC),
    CONSTRAINT [FK_dbo.AspNetUserClaims_dbo.AspNetUsers_User_Id] FOREIGN KEY ([UserId]) REFERENCES [dbo].[AspNetUsers] ([Id]) ON DELETE CASCADE
);

GO
CREATE NONCLUSTERED INDEX [IX_User_Id]
    ON [dbo].[AspNetUserClaims]([UserId] ASC);

CREATE TABLE [dbo].[AspNetUserLogins] (
    [UserId]        NVARCHAR (128) NOT NULL,
    [LoginProvider] NVARCHAR (128) NOT NULL,
    [ProviderKey]   NVARCHAR (128) NOT NULL,
    CONSTRAINT [PK_dbo.AspNetUserLogins] PRIMARY KEY CLUSTERED ([UserId] ASC, [LoginProvider] ASC, [ProviderKey] ASC),
    CONSTRAINT [FK_dbo.AspNetUserLogins_dbo.AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [dbo].[AspNetUsers] ([Id]) ON DELETE CASCADE
);

GO
CREATE NONCLUSTERED INDEX [IX_UserId]
    ON [dbo].[AspNetUserLogins]([UserId] ASC);
